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
	var ar *AutoRenew

	argParse := flag.NewFlagSet("cmd-import", flag.ExitOnError)
	var autoRenew = argParse.Bool("auto-renew", false, "Renew auto renawable certificates that will expire")
	var csr = argParse.String("csr", "", "Certificate signing request used for certificate creation")
	var delta = argParse.Int64("delta", 0, "For auto renewable certificates the auto renew process starts if the time til expiration is less than <delta_period> days")
	var period = argParse.Int64("period", 0, "New validity period for auto renewed certificate")
	var revoked = argParse.String("revoked", "", "Mark certificate as revoked")
	argParse.Usage = showHelpImport
	argParse.Parse(args)

	cmdImportTrailing := argParse.Args()
	if len(cmdImportTrailing) > 1 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	if len(cmdImportTrailing) == 0 {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(cmdImportTrailing[0])
	}
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	pblock, _ := pem.Decode(data)
	if pblock == nil {
		return fmt.Errorf("%s: Can't decode provided data into a certificate", GetFrame())
	}

	ic.Certificate, err = x509.ParseCertificate(pblock.Bytes)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	ar = &AutoRenew{
		SerialNumber:         ic.Certificate.SerialNumber,
		AutoRenewStartPeriod: cfg.Global.AutoRenewStartPeriod,
		ValidityPeriod:       cfg.Global.ValidityPeriod,
	}

	if *autoRenew {
		ic.AutoRenew = ar
	}

	if *csr != "" {
		data, err = ioutil.ReadFile(*csr)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		pblock, _ = pem.Decode(data)
		ic.CSR, err = x509.ParseCertificateRequest(pblock.Bytes)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if *delta != 0 {
		if *delta < 0 {
			return fmt.Errorf("%s: AutoRenewStartPeriod must be greater than 0", GetFrame())
		}
		if ic.AutoRenew == nil {
			ic.AutoRenew = ar
		}
		ic.AutoRenew.AutoRenewStartPeriod = *delta
	}

	if *period != 0 {
		if *period < 0 {
			return fmt.Errorf("%s: ValidityPeriod must be greater than 0", GetFrame())
		}
		if ic.AutoRenew == nil {
			ic.AutoRenew = ar
		}
		ic.AutoRenew.ValidityPeriod = *period
	}

	ic.AutoRenew.AutoRenewStartPeriod *= 86400
	ic.AutoRenew.ValidityPeriod *= 86400

	if *revoked != "" {
		_revoked := strings.Split(*revoked, ",")
		if len(_revoked) == 1 {
			ic.Revoked = &RevokeRequest{
				SerialNumber: ic.Certificate.SerialNumber,
				Reason:       _revoked[0],
				Time:         time.Now(),
			}
		} else if len(_revoked) == 2 {
			ic.Revoked = &RevokeRequest{
				SerialNumber: ic.Certificate.SerialNumber,
				Reason:       _revoked[0],
			}
			_t, err := time.Parse(ASN1GeneralizedTimeFormat, _revoked[1])
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			ic.Revoked.Time = _t
		} else {
			return fmt.Errorf("%s: Invalid format for revocation option", GetFrame())
		}
	}

	err = cfg.DBBackend.StoreCertificate(cfg, &ic, false)
	if err != nil {
		return err
	}

	return nil
}
