package main

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"time"
)

func ocspHandler(response http.ResponseWriter, request *http.Request) {
	var pubKeyInfo PublicKeyInformation
	var ocspRequest *ocsp.Request
	var err error
	var ocspResponse ocsp.Response
	var reply []byte

	defer func() {
		// Prevent memory leak by consuming content body
		ioutil.ReadAll(request.Body)
		request.Body.Close()
	}()

	// Always return data to the garbage collector
	defer func() {
		reply = nil
	}()

	if request.Header.Get("content-type") != "application/ocsp-request" {
		response.WriteHeader(http.StatusUnsupportedMediaType)
		fmt.Fprintf(response, "415 Unsupported Media Type")
		return
	}

	switch request.Method {
	case "GET": // XXX: Handle OCSP requests using HTTP GET:
		response.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(response, "501 Not Implemented")
		return
		/*
		 * An OCSP request using the GET method is constructed as follows:
		 *
		 * GET {url}/{url-encoding of base-64 encoding of the DER encoding of
		 * the OCSPRequest}
		 *
		 * where {url} may be derived from the value of AuthorityInfoAccess or
		 * other local configuration of the OCSP client.
		 */

	case "POST":
		if request.URL.Path != config.OCSP.Path {
			LogMessage(config, LogLevelWarning, fmt.Sprintf("Requested URL path %s is not the configured OCSP path %s", request.URL.Path, config.OCSP.Path))
			response.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(response, "404 Not Found")
			return
		}
		payload, err := ioutil.ReadAll(request.Body)
		if err != nil {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("Can't read request body: %s", err.Error()))
			response.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(response, err.Error())
			return
		}

		ocspRequest, err = parseOCSPRequest(payload)
		if err != nil {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("Can't parse OCSP request: %s", err.Error()))
			response.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(response, err.Error())
			return
		}

	default:
		LogMessage(config, LogLevelWarning, fmt.Sprintf("Unsupported HTTP methods %s", request.Method))
		response.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(response, "405 Method Not Allowed")
		return
	}

	// XXX: Check issuer issuerNameHash and issuerKeyHash
	hf := ocspRequest.HashAlgorithm.New()

	_, err = asn1.Unmarshal(config.CAPublicKey.RawSubjectPublicKeyInfo, &pubKeyInfo)
	if err != nil {
		LogMessage(config, LogLevelCritical, fmt.Sprintf("Can't unmarshal ASN1 data from OCSP request: %s", err.Error()))

		// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
		// at https://tools.ietf.org/html/rfc6960#section-2.3
		writeOCSPResponse(response, ocsp.InternalErrorErrorResponse)
		return
	}

	hf.Write(pubKeyInfo.PublicKey.RightAlign())
	caKeyHash := hf.Sum(nil)

	hf.Reset()
	hf.Write(config.CAPublicKey.RawSubject)
	caNameHash := hf.Sum(nil)

	if bytes.Equal(caKeyHash, ocspRequest.IssuerKeyHash) && bytes.Equal(caNameHash, ocspRequest.IssuerNameHash) {
		found, err := config.DBBackend.IsUsedSerialNumber(config, ocspRequest.SerialNumber)
		if err != nil {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("Connection to database backend failed: %s", err.Error()))

			// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
			// at https://tools.ietf.org/html/rfc6960#section-2.3
			writeOCSPResponse(response, ocsp.InternalErrorErrorResponse)
			return
		}
		if !found {
			ocspResponse.Status = ocsp.Unknown
		} else {
			info, err := config.DBBackend.GetCertificateInformation(config, ocspRequest.SerialNumber)
			if err != nil {
				LogMessage(config, LogLevelCritical, fmt.Sprintf("Connection to database backend failed: %s", err.Error()))

				// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
				// at https://tools.ietf.org/html/rfc6960#section-2.3
				writeOCSPResponse(response, ocsp.InternalErrorErrorResponse)
				return
			}
			ocspResponse.SerialNumber = ocspRequest.SerialNumber
			// Note: We do not set NextUpdate because newer revocation information
			//       are always available.
			ocspResponse.ThisUpdate = time.Now()

			dgst, found := DigestHashMap[config.Global.OcspDigest]
			if !found {
				LogMessage(config, LogLevelCritical, fmt.Sprintf("Configured OCSP digest %s not found", config.Global.OcspDigest))

				// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
				// at https://tools.ietf.org/html/rfc6960#section-2.3
				writeOCSPResponse(response, ocsp.InternalErrorErrorResponse)
				return
			}

			ocspResponse.IssuerHash = dgst

			if info.Revoked != nil {
				ocspResponse.Status = ocsp.Revoked
				ocspResponse.RevokedAt = info.Revoked.Time
				reason, found := RevocationReasonMap[info.Revoked.Reason]

				// This should NEVER happen!
				if !found {
					LogMessage(config, LogLevelCritical, fmt.Sprintf("Can't map revocation reason %s to numerical value", info.Revoked.Reason))

					// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
					// at https://tools.ietf.org/html/rfc6960#section-2.3
					writeOCSPResponse(response, ocsp.InternalErrorErrorResponse)
					return
				}
				// Don't report unused value of "7", report "unspecified" instead
				if reason == 7 {
					reason = 0
				}
				ocspResponse.RevocationReason = reason
			} else {
				ocspResponse.Status = ocsp.Good
			}
		}

		// TODO: Create signed OCSP response
		// reply, err = ocsp.CreateResponse(config.CAPublicKey, config.OCSPPublicKey, ocspResponse, config.OCSPCertificate.PrivateKey)
		key, ok := config.OCSPCertificate.PrivateKey.(crypto.Signer)
		if !ok {
			LogMessage(config, LogLevelCritical, "x509: certificate private key does not implement crypto.Signer")

			response.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(response, "405 Method Not Allowed\nx509: certificate private key does not implement crypto.Signer\n")
			return
		}

		reply, err = ocsp.CreateResponse(config.CAPublicKey, config.OCSPPublicKey, ocspResponse, key)
		if err != nil {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("Can't create OCSP response: %s", err.Error()))

			// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
			// at https://tools.ietf.org/html/rfc6960#section-2.3
			writeOCSPResponse(response, ocsp.InternalErrorErrorResponse)
			return
		}

	} else {
		// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
		// at https://tools.ietf.org/html/rfc6960#section-2.3
		reply = ocsp.UnauthorizedErrorResponse
	}

	writeOCSPResponse(response, reply)
	return
}
