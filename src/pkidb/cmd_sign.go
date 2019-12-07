package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// CmdSign - Command "sign"
func CmdSign(cfg *PKIConfiguration, args []string) error {
	var sr SigningRequest
	var validityPeriod int
	var csrData *x509.CertificateRequest
	var err error
	var fd *os.File

	argParse := flag.NewFlagSet("cmd-sign", flag.ExitOnError)
	var extensions = argParse.String("extension", "", "X509 extension. Can be repeated for multiple extensions")
	var extendedKeyUsage = argParse.String("extended-keyusage", "", "Comma separated list of extended key usage bits")
	var san = argParse.String("san", "", "subjectAltName extension")
	var autoRenew = argParse.Bool("auto-renew", false, "Mark certificate as auto renewable")
	var basicConstraint = argParse.String("basic-constraint", "", "Set basic constraints prefix critical")
	var keyUsage = argParse.String("keyusage", "", "Comma separated list of keyUsage bits")
	var noRegister = argParse.Bool("no-register", false, "Don't store certificate data - except the serial number - in the database")
	var output = argParse.String("output", "", "Write data to <outfile> instead of stdout")
	var startIn = argParse.Int("start-in", 0, "Validity of the new certificate starts in startin days")
	var template = argParse.String("template", "", "Use a template file for certificate signing")
	var validFor = argParse.Int("valid-for", 0, "ew certificate will be valid for validfor days")
	argParse.Parse(args)

	if cfg.Global.CaPublicKey == "" || cfg.Global.CaPrivateKey == "" {
		return fmt.Errorf("")
	}

	cmdSignTrailing := argParse.Args()
	if len(cmdSignTrailing) > 1 {
		return fmt.Errorf("Too many arguments")
	}

	if len(cmdSignTrailing) == 0 {
		csrData, err = ReadCSR("")
	} else {
		csrData, err = ReadCSR(cmdSignTrailing[0])
	}
	if err != nil {
		return err
	}
	sr.CSRData = csrData

	if *extensions != "" {
		sr.Extension = make([]X509ExtensionData, 0)
		for _, ext := range strings.Split(*extensions, ",") {
			e := X509ExtensionData{}

			rawExt := strings.Split(ext, ":")
			if len(rawExt) != 3 {
				return fmt.Errorf("Invalid extension data")
			}

			e.Name = rawExt[0]

			if rawExt[1] == "" || rawExt[1] == "0" {
				e.Critical = false
			} else if rawExt[1] == "1" {
				e.Critical = true
			} else {
				return fmt.Errorf("Invalid extension data")
			}

			if rawExt[2] != "" {
				e.Data, err = base64.StdEncoding.DecodeString(rawExt[2])
				if err != nil {
					return err
				}
			}
			sr.Extension = append(sr.Extension, e)
		}
	}

	if *extendedKeyUsage != "" {
		sr.ExtendedKeyUsage = make([]X509ExtendedKeyUsageData, 0)
		for _, eku := range strings.Split(*extendedKeyUsage, ",") {
			ekud := X509ExtendedKeyUsageData{}
			ekud.Critical = false
			ekud.Flags = eku
			sr.ExtendedKeyUsage = append(sr.ExtendedKeyUsage, ekud)
		}
	}

	if *san != "" {
		sr.SAN = make([]X509SubjectAlternateNameData, 0)
		for _, san := range strings.Split(*san, ",") {
			_san := X509SubjectAlternateNameData{}
			rawSan := strings.Split(san, ":")
			if len(rawSan) == 2 {
				_san.Type = strings.ToLower(rawSan[0])
				_san.Value = rawSan[1]
			} else {
				return fmt.Errorf("Invalid subject alternate name option")
			}

			sr.SAN = append(sr.SAN, _san)
		}
	}
	if *autoRenew {
		sr.AutoRenew = true
	}

	if *basicConstraint != "" {
		sr.BasicConstraint = make([]X509BasicConstraintData, 0)
		for _, bcd := range strings.Split(*basicConstraint, ",") {
			_bcd := X509BasicConstraintData{}
			rawBcd := strings.Split(bcd, ":")
			if len(rawBcd) == 2 {
				_bcd.Type = rawBcd[0]
				_bcd.Value = rawBcd[1]
			} else {
				return fmt.Errorf("Invalid basic constraint data")
			}
			sr.BasicConstraint = append(sr.BasicConstraint, _bcd)
		}
	}

	if *keyUsage != "" {
		sr.KeyUsage = make([]X509KeyUsageData, 0)
		for _, kus := range strings.Split(*keyUsage, ",") {
			_kus := X509KeyUsageData{}
			_kus.Type = kus
			_kus.Critical = true
			sr.KeyUsage = append(sr.KeyUsage, _kus)
		}
	}

	if *noRegister {
		sr.NoRegistration = true
	}

	if *startIn != 0 {
		sr.NotBefore = time.Now().Add(time.Duration(24) * time.Duration(*startIn) * time.Hour)
	} else {
		sr.NotBefore = time.Now()
	}

	// TODO
	validityPeriod = cfg.Global.ValidityPeriod
	if *template != "" {
	}

	// TODO
	if *validFor != 0 {
		if *validFor < 0 {
			return fmt.Errorf("Validity period can't be negative")
		}
		if *validFor > 0 {
			validityPeriod = *validFor
		}
	}

	sr.NotAfter = sr.NotBefore.Add(time.Duration(24) * time.Duration(validityPeriod) * time.Hour)

	newCert, err := signRequest(cfg, &sr)
	if err != nil {
		return err
	}

	if *output != "" {
		fd, err = os.Create(*output)
		if err != nil {
			return err
		}
	} else {
		fd = os.Stdout
	}

	err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: newCert})
	if err != nil {
		return err
	}

	// This should never fail ...
	cert, err := x509.ParseCertificate(newCert)
	if err != nil {
		return err
	}

	if *noRegister {
		// at least change type of record for locked serial to from "temporary" to "dummy"
		err = cfg.DBBackend.LockSerialNumber(cfg, cert.SerialNumber, PKICertificateStatusDummy, true)
		if err != nil {
			return err
		}
	} else {
		ci := &ImportCertificate{
			Certificate: cert,
			CSR:         sr.CSRData,
		}
		if sr.AutoRenew {
			ar := &AutoRenew{
				SerialNumber: cert.SerialNumber,
				Delta:        cfg.Global.AutoRenewStartPeriod,
				Period:       cfg.Global.ValidityPeriod,
			}
			ci.AutoRenew = ar
		}
		err = cfg.DBBackend.StoreCertificate(cfg, ci, true)
		if err != nil {
			return err
		}
	}

	if *output != "" {
		err = fd.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

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
