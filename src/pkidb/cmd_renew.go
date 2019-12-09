package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"
)

// CmdRenew - renew command
func CmdRenew(cfg *PKIConfiguration, args []string) error {
	var err error
	var snList = make([]string, 0)
	var splitted []string
	var serial *big.Int
	var newEnd time.Time
	var fd *os.File
	var oldCSR *x509.CertificateRequest

	argParse := flag.NewFlagSet("cmd-renew", flag.ExitOnError)
	var output = argParse.String("output", "", "Write new certificate to <output> instead of standard out")
	var period = argParse.Int("period", 0, "New validity period for renewed certificate")
	argParse.Usage = showHelpRenew
	argParse.Parse(args)

	cmdRenewTrailing := argParse.Args()
	if len(cmdRenewTrailing) == 0 {
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
		splitted = cmdRenewTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			snList = append(snList, strings.TrimSpace(v))
		}
	}

	if *period != 0 {
		if *period < 0 {
			return fmt.Errorf("%s: New validity period must be positive", GetFrame())
		}
		newEnd = time.Now().Add(time.Duration(24) * time.Hour * time.Duration(*period))
	} else {
		newEnd = time.Now().Add(time.Duration(24) * time.Hour * time.Duration(cfg.Global.ValidityPeriod))
	}

	if *output != "" {
		fd, err = os.Create(*output)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	} else {
		fd = os.Stdout
	}

	for _, s := range snList {
		serial = big.NewInt(0)
		serial, ok := serial.SetString(s, 0)
		if !ok {
			return fmt.Errorf("%s: Can't convert serial number %s to big integer", GetFrame(), s)
		}

		// get known ceritificate information from database
		certinfo, err := cfg.DBBackend.GetCertificateInformation(cfg, serial)
		if err != nil {
			return err
		}
		if certinfo.Revoked != nil {
			return fmt.Errorf("%s: Certificate with serial number %s has been revoked on %s (reason: %s)", GetFrame(), s, certinfo.Revoked.Time.Format(OutputTimeFormat), certinfo.Revoked.Reason)
		}

		raw, err := RenewCertificate(cfg, serial, newEnd)
		if err != nil {
			return err
		}

		// This should never fail ...
		ncert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		// Update certificate data in database ...
		if certinfo.CSR != "" {
			rawCSR, err := base64.StdEncoding.DecodeString(certinfo.CSR)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}

			oldCSR, err = x509.ParseCertificateRequest(rawCSR)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		} else {
			oldCSR = nil
		}

		// create import struct
		imp := &ImportCertificate{
			Certificate: ncert,
			AutoRenew:   certinfo.AutoRenewable,
			Revoked:     certinfo.Revoked,
			CSR:         oldCSR,
		}
		err = cfg.DBBackend.StoreCertificate(cfg, imp, true)
		if err != nil {
			return err
		}

		// change state from expired to valid
		if certinfo.State == "expired" {
			err = cfg.DBBackend.StoreState(cfg, serial, "valid")
			if err != nil {
				return nil
			}
		}

		err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: raw})
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if *output != "" {
		err = fd.Close()
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	return nil
}
