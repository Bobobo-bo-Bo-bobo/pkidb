package main

import (
    "crypto/x509"
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

	argParse := flag.NewFlagSet("cmd-renew", flag.ExitOnError)
	var output = argParse.String("output", "", "Write new certificate to <output> instead of standard out")
	var period = argParse.Int("period", 0, "New validity period for renewed certificate")
	argParse.Usage = showHelpRenew
	argParse.Parse(args)

	cmdRenewTrailing := argParse.Args()
	if len(cmdRenewTrailing) == 0 {
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
		splitted = cmdRenewTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			snList = append(snList, strings.TrimSpace(v))
		}
	}

	if *period != 0 {
		if *period < 0 {
			return fmt.Errorf("New validity period must be positive")
		}
		newEnd = time.Now().Add(time.Duration(24) * time.Hour * time.Duration(*period))
	} else {
		newEnd = time.Now().Add(time.Duration(24) * time.Hour * time.Duration(cfg.Global.ValidityPeriod))
	}

	if *output != "" {
		fd, err = os.Create(*output)
		if err != nil {
			return err
		}
	} else {
		fd = os.Stdout
	}

	for _, s := range snList {
		serial = big.NewInt(0)
		serial, ok := serial.SetString(s, 0)
		if !ok {
			return fmt.Errorf("Can't convert serial number %s to big integer", s)
		}

		raw, err := RenewCertificate(cfg, serial, newEnd)
		if err != nil {
			return err
		}

		// This should never fail ...
		_, err = x509.ParseCertificate(raw)
		if err != nil {
			return err
		}

        // TODO: Update certificate data in database ... StoreCertificate

		err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: raw})
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
