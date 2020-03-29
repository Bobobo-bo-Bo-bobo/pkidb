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
	var _rstr = ""

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
		if config.Global.ListAsHex {
			LogMessage(config, LogLevelInfo, fmt.Sprintf("OCSP request from %s for serial number 0x%s", request.RemoteAddr, ocspRequest.SerialNumber.Text(16)))
		} else {
			LogMessage(config, LogLevelInfo, fmt.Sprintf("OCSP request from %s for serial number %s", request.RemoteAddr, ocspRequest.SerialNumber.Text(10)))
		}

		found, err := config.DBBackend.IsUsedSerialNumber(config, ocspRequest.SerialNumber)
		if err != nil {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("Connection to database backend failed: %s", err.Error()))

			// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
			// at https://tools.ietf.org/html/rfc6960#section-2.3
			writeOCSPResponse(response, ocsp.InternalErrorErrorResponse)
			return
		}
		if !found {
			if config.Global.ListAsHex {
				LogMessage(config, LogLevelWarning, fmt.Sprintf("Requested serial number 0x%s not found in database backend", ocspRequest.SerialNumber.Text(16)))
			} else {
				LogMessage(config, LogLevelWarning, fmt.Sprintf("Requested serial number %s not found in database backend", ocspRequest.SerialNumber.Text(10)))
			}

			_rstr = "unknown"
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
				_rstr = "revoked"

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

				if config.Global.ListAsHex {
					LogMessage(config, LogLevelInfo, fmt.Sprintf("Requested serial number 0x%s has been revoked at %s, reason %s", ocspRequest.SerialNumber.Text(16), info.Revoked.Time, info.Revoked.Reason))
				} else {
					LogMessage(config, LogLevelInfo, fmt.Sprintf("Requested serial number %s has been revoked at %s, reason %s", ocspRequest.SerialNumber.Text(10), info.Revoked.Time, info.Revoked.Reason))
				}

				// Don't report unused value of "7", report "unspecified" instead
				if reason == 7 {
					reason = 0
				}
				ocspResponse.RevocationReason = reason
			} else {
				_rstr = "good"
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
		if config.Global.ListAsHex {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("We are not responsible for serial number 0x%s (IssuerHash and/or NameHash from OCSP request don't match with values from our CA), rejecting request from %s", ocspRequest.SerialNumber.Text(16), request.RemoteAddr))
		} else {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("We are not responsible for serial number %s (IssuerHash and/or NameHash from OCSP request don't match with values from our CA), rejecting request from %s", ocspRequest.SerialNumber.Text(10), request.RemoteAddr))
		}

		// OCSP errors are _not_ signed, see RFC 6960 - 2.3.  Exception Cases
		// at https://tools.ietf.org/html/rfc6960#section-2.3
		_rstr = "unauthorized"
		reply = ocsp.UnauthorizedErrorResponse
	}

	if config.Global.ListAsHex {
		LogMessage(config, LogLevelInfo, fmt.Sprintf("Sending OCSP response '%s' for serial number 0x%s to %s", _rstr, ocspRequest.SerialNumber.Text(16), request.RemoteAddr))
	} else {
		LogMessage(config, LogLevelInfo, fmt.Sprintf("Sending OCSP response '%s' for serial number %s to %s", _rstr, ocspRequest.SerialNumber.Text(10), request.RemoteAddr))
	}
	writeOCSPResponse(response, reply)
	return
}
