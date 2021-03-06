package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

// CmdSet - set meta data
func CmdSet(cfg *PKIConfiguration, args []string) error {
	var splitted []string
	var snList []string
	var err error
	var csr *x509.CertificateRequest
	var renewStart int64
	var renewPeriod int64

	argParse := flag.NewFlagSet("cmd-set", flag.ExitOnError)
	var autoRenew = argParse.Bool("auto-renew", false, "Mark a certificate as auto renewable")
	var autoRenewStartPeriod = argParse.Int64("auto-renew-start-period", 0, "Set auto renew start period in days")
	var autoRenewValidityPeriod = argParse.Int64("auto-renew-validity-period", 0, "Renew the certificate for <period> days")
	var noAutoRenew = argParse.Bool("no-auto-renew", false, "Remove auto renewable argParse from certificate meta data")
	var csrFile = argParse.String("csr", "", "Set certificate signing request")
	argParse.Usage = showHelpSet
	argParse.Parse(args)

	cmdSetTrailing := argParse.Args()
	if len(cmdSetTrailing) == 0 {
		raw, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		rawstr := string(raw)
		rawstr = strings.Replace(rawstr, "\r", "", -1)
		rawstr = strings.Replace(rawstr, "\n", " ", -1)
		rawstr = strings.Replace(rawstr, "\t", " ", -1)

		splitted = strings.Split(rawstr, " ")
	} else {
		splitted = cmdSetTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			snList = append(snList, strings.TrimSpace(v))
		}
	}

	if *csrFile != "" {
		csr, err = ReadCSR(*csrFile)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if *autoRenewStartPeriod > 0 {
		*autoRenew = true
	}
	if *autoRenewStartPeriod < 0 {
		return fmt.Errorf("%s: auto-renew-start-period must be positive", GetFrame())
	}

	if *autoRenewValidityPeriod > 0 {
		*autoRenew = true
	}
	if *autoRenewValidityPeriod < 0 {
		return fmt.Errorf("%s: auto-renew-validity-period must be positive", GetFrame())
	}

	if *autoRenew && *noAutoRenew {
		return fmt.Errorf("%s: Invalid combination of options. --auto-renew and no-auto-renew are mutually exclusive", GetFrame())
	}

	for _, sn := range snList {
		serial := big.NewInt(0)
		serial, ok := serial.SetString(sn, 0)
		if !ok {
			return fmt.Errorf("%s: Can't convert serial number %s to big integer", GetFrame(), sn)
		}

		if csr != nil {
			imp := &ImportCertificate{
				Certificate: &x509.Certificate{SerialNumber: serial},
				CSR:         csr,
			}
			err = cfg.DBBackend.StoreCertificateSigningRequest(cfg, imp)
			if err != nil {
				return err
			}
		}

		if *autoRenew {
			if *autoRenewStartPeriod > 0 {
				renewStart = *autoRenewStartPeriod
			} else {
				renewStart = cfg.Global.AutoRenewStartPeriod
			}

			if *autoRenewValidityPeriod > 0 {
				renewPeriod = *autoRenewValidityPeriod
			} else {
				renewPeriod = cfg.Global.ValidityPeriod
			}

			ar := &AutoRenew{
				SerialNumber:         serial,
				AutoRenewStartPeriod: renewStart * 86400,
				ValidityPeriod:       renewPeriod * 86400,
			}

			err = cfg.DBBackend.StoreAutoRenew(cfg, ar)
			if err != nil {
				return err
			}
		}

		if *noAutoRenew {
			cfg.DBBackend.DeleteAutoRenew(cfg, serial)
			if err != nil {
				return err
			}
		}
		LogMessage(cfg, LogLevelInfo, fmt.Sprintf("Meta information set for certificate with serial number %s", sn))
	}
	return nil
}
