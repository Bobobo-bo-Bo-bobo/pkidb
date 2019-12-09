package main

import (
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

// CmdExport - export certificate
func CmdExport(cfg *PKIConfiguration, args []string) error {
	var snList = make([]string, 0)
	var splitted []string
	var fd *os.File
	var err error
	var data strings.Builder
	var serial *big.Int

	argParse := flag.NewFlagSet("cmd-export", flag.ExitOnError)
	var output = argParse.String("output", "", "Write certificate information to <output> instead of standard output")
	argParse.Usage = showHelpExport
	argParse.Parse(args)

	cmdExportTrailing := argParse.Args()
	if len(cmdExportTrailing) == 0 {
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
		splitted = cmdExportTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			snList = append(snList, strings.TrimSpace(v))
		}
	}

	for _, sn := range snList {
		serial = big.NewInt(0)
		serial, ok := serial.SetString(sn, 0)
		if !ok {
			return fmt.Errorf("%s: Invalid serial number %s", GetFrame(), sn)
		}

		ci, err := cfg.DBBackend.GetCertificateInformation(cfg, serial)
		if err != nil {
			return err
		}

		if ci.PublicKey != "" {
			decoded, err := base64.StdEncoding.DecodeString(ci.PublicKey)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			err = pem.Encode(&data, &pem.Block{Type: "CERTIFICATE", Bytes: decoded})
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	if *output == "" {
		fd = os.Stdout
	} else {
		fd, err = os.Create(*output)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	_, err = fmt.Fprintf(fd, "%s", data.String())
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	if *output != "" {
		err = fd.Close()
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	return nil
}
