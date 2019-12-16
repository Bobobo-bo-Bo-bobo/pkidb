package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"
)

// CmdRevoke - revoke a certificate
func CmdRevoke(cfg *PKIConfiguration, args []string) error {
	var err error
	var snList = make([]string, 0)
	var splitted []string
	var revtime time.Time
	var serial *big.Int

	argParse := flag.NewFlagSet("cmd-revoke", flag.ExitOnError)
	var force = argParse.Bool("force", false, "Revoke certificate by it's serial number event it is not present in the database")
	var reason = argParse.String("reason", "unspecified", "Set revocation reason for certificate")
	var rdate = argParse.String("revocation-date", "", "Set revocation date for certificate")
	argParse.Usage = showHelpRevoke
	argParse.Parse(args)

	cmdRevokeTrailing := argParse.Args()
	if len(cmdRevokeTrailing) == 0 {
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
		splitted = cmdRevokeTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			snList = append(snList, strings.TrimSpace(v))
		}
	}

	if *rdate != "" {
		revtime, err = time.Parse(ASN1GeneralizedTimeFormat, *rdate)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	} else {
		revtime = time.Now()
	}

	for _, sn := range snList {
		serial = big.NewInt(0)
		serial, ok := serial.SetString(sn, 0)
		if !ok {
			return fmt.Errorf("%s: Invalid serial number %s", GetFrame(), sn)
		}

		// check if certificate has already been revoked
		info, err := cfg.DBBackend.GetCertificateInformation(cfg, serial)
		if err != nil {
			return err
		}
		if info.Revoked != nil {
			return fmt.Errorf("%s: Certificate with serial number %s was already revoked", GetFrame(), sn)
		}

		rr := &RevokeRequest{
			SerialNumber: serial,
			Reason:       *reason,
			Force:        *force,
			Time:         revtime,
		}
		err = cfg.DBBackend.StoreRevocation(cfg, rr)
		if err != nil {
			return err
		}
		LogMessage(cfg, LogLevelInfo, fmt.Sprintf("Certificate with serial number %s revoked", sn))
	}
	return nil
}
