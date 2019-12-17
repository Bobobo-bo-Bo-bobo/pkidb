package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"
)

// CmdSign - Command "sign"
func CmdSign(cfg *PKIConfiguration, args []string) error {
	var sr SigningRequest
	var validityPeriod int64
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
	var validFor = argParse.Int64("valid-for", 0, "New certificate will be valid for validfor days")
	argParse.Usage = showHelpSign
	argParse.Parse(args)

	if len(cfg.Global.caPublicKey) == 0 || len(cfg.Global.caPrivateKey) == 0 {
		return fmt.Errorf("%s: Public and private key for signing CA must be defined", GetFrame())
	}

	cmdSignTrailing := argParse.Args()
	if len(cmdSignTrailing) > 1 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	if cfg.CAPublicKey == nil || cfg.CACertificate == nil {
		return fmt.Errorf("%s: No public/private key for signing CA", GetFrame())
	}

	if len(cmdSignTrailing) == 0 {
		csrData, err = ReadCSR("")
	} else {
		csrData, err = ReadCSR(cmdSignTrailing[0])
	}
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	sr.CSRData = csrData

	if *template != "" {
		templateContent, err := ParseTemplateFile(*template)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		if len(templateContent.Extension) != 0 {
			sr.Extension = templateContent.Extension
		}

		if len(templateContent.KeyUsage) != 0 {
			sr.KeyUsage = templateContent.KeyUsage
		}

		if len(templateContent.ExtendedKeyUsage) != 0 {
			sr.ExtendedKeyUsage = templateContent.ExtendedKeyUsage
		}

		// Note: We don't "chain" commands in a single call, so it is o.k. to simply replace
		//       the values in the PKIConfiguration structure. We exit when we are done.
		if templateContent.Global.Digest != "" {
			cfg.Global.Digest = templateContent.Global.Digest
		}
		if templateContent.Global.ValidityPeriod != 0 {
			cfg.Global.ValidityPeriod = templateContent.Global.ValidityPeriod
		}
		if templateContent.Global.AutoRenewStartPeriod != 0 {
			cfg.Global.AutoRenewStartPeriod = templateContent.Global.AutoRenewStartPeriod
		}
		if templateContent.Global.CrlValidityPeriod != 0 {
			cfg.Global.CrlValidityPeriod = templateContent.Global.CrlValidityPeriod
		}
		if templateContent.Global.CrlDigest != "" {
			cfg.Global.CrlDigest = templateContent.Global.CrlDigest
		}
	}

	if *extensions != "" {
		sr.Extension, err = ParseExtensionString(*extensions)
		if err != nil {
			return err
		}
	}

	if *extendedKeyUsage != "" {
		sr.ExtendedKeyUsage, err = ParseExtendedKeyUsageString(*extendedKeyUsage)
		if err != nil {
			return err
		}
	}

	if *san != "" {
		sr.SAN, err = ParseSANString(*san)
		if err != nil {
			return err
		}
	}
	if *autoRenew {
		sr.AutoRenew = true
	}

	if *basicConstraint != "" {
		sr.BasicConstraint, err = ParseBasicConstraintString(*basicConstraint)
		if err != nil {
			return err
		}
	}

	if *keyUsage != "" {
		sr.KeyUsage, err = ParseKeyUsageString(*keyUsage)
		if err != nil {
			return err
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

	validityPeriod = cfg.Global.ValidityPeriod
	if *validFor != 0 {
		if *validFor < 0 {
			return fmt.Errorf("%s: Validity period can't be negative", GetFrame())
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

	// This should never fail ...
	cert, err := x509.ParseCertificate(newCert)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
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
				SerialNumber:         cert.SerialNumber,
				AutoRenewStartPeriod: cfg.Global.AutoRenewStartPeriod * 86400,
				ValidityPeriod:       cfg.Global.ValidityPeriod * 86400,
			}
			ci.AutoRenew = ar
		}
		err = cfg.DBBackend.StoreCertificate(cfg, ci, true)
		if err != nil {
			return err
		}
	}

	if *output != "" {
		fd, err = os.Create(*output)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	} else {
		fd = os.Stdout
	}

	err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: newCert})
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if *output != "" {
		err = fd.Close()
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	LogMessage(cfg, LogLevelInfo, fmt.Sprintf("Certificate with serial number %s created from certificate signing request", cert.SerialNumber))
	return nil
}
