package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"
)

// CmdAddDummy - add dummy certificate
func CmdAddDummy(cfg *PKIConfiguration, args []string) error {
	var serial *big.Int
	var notBefore time.Time
	var notAfter time.Time
	var snList = make([]string, 0)
	var err error
	var splitted []string
	var ok bool

	argParse := flag.NewFlagSet("cmd-add-dummy", flag.ExitOnError)
	var subject = argParse.String("subject", "", "Certificate subject")
	var start = argParse.String("start", "", "Start of the certificates validity period")
	var end = argParse.String("end", "", "End of the certificates validity period")
	argParse.Parse(args)

	cmdAddDummyTrailing := argParse.Args()
	if len(cmdAddDummyTrailing) == 0 {
		raw, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		rawstr := string(raw)
		rawstr = strings.Replace(rawstr, "\r", "", -1)
		rawstr = strings.Replace(rawstr, "\n", " ", -1)
		rawstr = strings.Replace(rawstr, "\t", " ", -1)

		splitted = strings.Split(rawstr, " ")
	} else {
		splitted = cmdAddDummyTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			snList = append(snList, strings.TrimSpace(v))
		}
	}

	if *start != "" {
		notBefore, err = time.Parse(ASN1GeneralizedTimeFormat, *start)
		if err != nil {
			return err
		}
	} else {
		notBefore = time.Now()
	}

	if *end != "" {
		notAfter, err = time.Parse(ASN1GeneralizedTimeFormat, *end)
		if err != nil {
			return err
		}
	} else {
		notAfter = notBefore.Add(time.Duration(24) * time.Duration(cfg.Global.ValidityPeriod) * time.Hour)
	}

	ci := &ImportCertificate{
		IsDummy:        true,
		DummyNotBefore: &notBefore,
		DummyNotAfter:  &notAfter,
	}
	if *subject == "" {
		ci.DummySubject = DummyCertificateSubject
	} else {
		ci.DummySubject = *subject
	}

	for _, sn := range snList {
		serial = big.NewInt(0)
		serial, ok = serial.SetString(sn, 0)
		if !ok {
			return fmt.Errorf("Invalid serial number %s", sn)
		}

		ci.Certificate = &x509.Certificate{SerialNumber: serial}
		err = cfg.DBBackend.StoreCertificate(cfg, ci, false)
		if err != nil {
			return err
		}
	}
	return nil
}
