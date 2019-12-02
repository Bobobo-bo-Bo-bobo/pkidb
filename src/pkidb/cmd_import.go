package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

// CmdImport - import a certificate
func CmdImport(cfg *PKIConfiguration, args []string) error {
	var err error
	var ic ImportCertificate
	var data []byte

	argParse := flag.NewFlagSet("cmd-import", flag.ExitOnError)
	var autoRenew = argParse.Bool("auto-renew", false, "Renew auto renawable certificates that will expire")
	var csr = argParse.String("csr", "", "Certificate signing request used for certificate creation")
	var delta = argParse.Int("delta", 0, "For auto renewable certificates the auto renew process starts if the time til expiration is less than <delta_period> days")
	var period = argParse.Int("period", 0, "New validity period for auto renewed certificate")
	var revoked = argParse.String("revoked", "", "Mark certificate as revoked")
	argParse.Parse(args)

	cmdImportTrailing := argParse.Args()
	if len(cmdImportTrailing) > 1 {
		return fmt.Errorf("Too many arguments")
	}

	if len(cmdImportTrailing) == 0 {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(cmdImportTrailing[0])
	}
	if err != nil {
		return err
	}

	pblock, _ := pem.Decode(data)
	ic.Certificate, err = x509.ParseCertificate(pblock.Bytes)
	if err != nil {
		return err
	}

	if *autoRenew {
		ic.AutoRenew = true
	}

	if *csr != "" {
		data, err = ioutil.ReadFile(*csr)
		if err != nil {
			return err
		}
		pblock, _ = pem.Decode(data)
		ic.CSR, err = x509.ParseCertificateRequest(data)
		if err != nil {
			return err
		}
	}

	if *delta != 0 {
		if *delta < 0 {
			return fmt.Errorf("Delta must be greater than 0")
		}
		ic.AutoRenewDelta = *delta
	}

	if *period != 0 {
		if *period < 0 {
			return fmt.Errorf("Period must be greater than 0")
		}
		ic.AutoRenewPeriod = *period
	}

	if *revoked != "" {
		_revoked := strings.Split(*revoked, ",")
		if len(_revoked) == 1 {
			ic.Revoked = true
			ic.RevokedReason = _revoked[0]
			ic.RevokedTime = time.Now()
		} else if len(_revoked) == 2 {
			ic.Revoked = true
			ic.RevokedReason = _revoked[0]
			ic.RevokedTime, err = time.Parse(ASN1GeneralizedTimeFormat, _revoked[1])
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Invalid format for revocation option")
		}
	}

	err = cfg.DBBackend.StoreCertificate(cfg, &ic, false)
	if err != nil {
		return err
	}

	return nil
}
