package main

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func signRequest(cfg *PKIConfiguration, sr *SigningRequest) ([]byte, error) {
	// parse provided CSR
	err := sr.CSRData.CheckSignature()
	if err != nil {
		return nil, err
	}

	// get new serial number
	newSerial, err := NewSerialNumber(cfg)
	if err != nil {
		return nil, err
	}
	// lock serial number in database
	// XXX: There is a slim but possible race condition here (especially if serial number algorithm is "increment"). Other call might use the same serial number and lock it.
	//      At the moment we simple ignore it
	err = cfg.DBBackend.LockSerialNumber(cfg, newSerial, PKICertificateStatusTemporary, false)
	if err != nil {
		return nil, err
	}

	dgst, found := DigestMap[cfg.Global.Digest]
	if !found {
		// remove locked serial number from the database
		err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Can't map digest %s to a signature algorithm", cfg.Global.Digest)
	}

	certTemplate := x509.Certificate{
		SerialNumber:       newSerial,
		Signature:          sr.CSRData.Signature,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          sr.CSRData.PublicKey,
		Subject:            sr.CSRData.Subject,
		NotBefore:          sr.NotBefore,
		NotAfter:           sr.NotAfter,
		SignatureAlgorithm: dgst,
		DNSNames:           make([]string, 0),
		EmailAddresses:     make([]string, 0),
		IPAddresses:        make([]net.IP, 0),
		URIs:               make([]*url.URL, 0),
	}

	for _, _san := range sr.SAN {
		// check and map SAN extension types. Go! supports DNS, email, IP, URI (but not RID, dirName and otherName ?)
		switch _san.Type {
		case "dns":
			certTemplate.DNSNames = append(certTemplate.DNSNames, _san.Value)
		case "email":
			certTemplate.EmailAddresses = append(certTemplate.EmailAddresses, _san.Value)
		case "ip":
			ip := net.ParseIP(_san.Value)
			if ip == nil {
				// remove locked serial number from the database
				err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("Can't convert %s to an IP address", _san.Value)
			}
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		case "uri":
			u, err := url.Parse(_san.Value)
			if err != nil {
				// remove locked serial number from the database
				err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("Can't convert %s to an URI", _san.Value)
			}
			certTemplate.URIs = append(certTemplate.URIs, u)
		default:
			return nil, fmt.Errorf("Unsupported subject alternate name type %s", _san.Type)
		}
	}

	// check and map keyUsage
	for _, ku := range sr.KeyUsage {
		keyusage, found := KeyUsageMap[strings.ToLower(ku.Type)]
		if !found {
			// remove locked serial number from the database
			err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Invalid key usage %s", ku.Type)
		}
		certTemplate.KeyUsage |= keyusage
	}

	// check and map extended key usage
	for _, eku := range sr.ExtendedKeyUsage {
		ekeyusage, found := ExtendedKeyUsageMap[strings.ToLower(eku.Flags)]
		if !found {
			oid, err := StringToASN1ObjectIdentifier(eku.Flags)
			if err != nil {
				// remove locked serial number from the database
				errdb := cfg.DBBackend.DeleteCertificate(cfg, newSerial)
				if errdb != nil {
					return nil, errdb
				}
				return nil, err
			}
			certTemplate.UnknownExtKeyUsage = append(certTemplate.UnknownExtKeyUsage, oid)
		} else {
			certTemplate.ExtKeyUsage = append(certTemplate.ExtKeyUsage, ekeyusage)
		}
	}

	// build X509 extensions
	for _, ext := range sr.Extension {
		pkixext, err := BuildX509Extension(ext)
		if err != nil {
			return nil, err
		}
		certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, pkixext)
	}

	// process basic constraints
	for _, bc := range sr.BasicConstraint {
		switch strings.ToLower(bc.Type) {
		case "ca":
			switch strings.ToLower(bc.Value) {
			case "true":
				certTemplate.IsCA = true
			case "false":
				certTemplate.IsCA = false
			default:
				// remove locked serial number from the database
				err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("Basic constraint CA is a boolean and only accepts true or false as value")
			}
		case "pathlen":
			pl, err := strconv.Atoi(bc.Value)
			if err != nil {
				// remove locked serial number from the database
				err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("Can't convert %s to an integer", bc.Value)
			}
			if pl < 0 {
				// remove locked serial number from the database
				err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("Pathlen can't be negative")
			}

			certTemplate.MaxPathLen = pl
			if pl == 0 {
				certTemplate.MaxPathLenZero = true
			}
		default:
			// remove locked serial number from the database
			err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("Invalid basic constraint %s", bc.Type)
		}
	}
	/*
	   RFC 5280 dictates:
	       "CAs MUST NOT include the pathLenConstraint field unless the cA
	       boolean is asserted and the key usage extension asserts the
	       keyCertSign bit."
	*/
	if !certTemplate.IsCA || !(certTemplate.KeyUsage&x509.KeyUsageCertSign == x509.KeyUsageCertSign) {
		if certTemplate.MaxPathLen > 0 || (certTemplate.MaxPathLen == 0 && certTemplate.MaxPathLenZero) {
			// remove locked serial number from the database
			err = cfg.DBBackend.DeleteCertificate(cfg, newSerial)
			if err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("Can't set pathlen constraint. CA constraint must be set and key usage must include keyCertSign")
		}
	}
	certTemplate.BasicConstraintsValid = true

	newCert, err := x509.CreateCertificate(rand.Reader, &certTemplate, cfg.CAPublicKey, sr.CSRData.PublicKey, cfg.CACertificate.PrivateKey)
	if err != nil {
		// remove locked serial number from the database
		errdb := cfg.DBBackend.DeleteCertificate(cfg, newSerial)
		if errdb != nil {
			return nil, errdb
		}
		return nil, err
	}
	return newCert, nil
}
