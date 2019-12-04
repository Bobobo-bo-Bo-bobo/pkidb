package main

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

// CmdDelete - delete certificate(s)
func CmdDelete(cfg *PKIConfiguration, args []string) error {
	var snList = make([]string, 0)
	var splitted []string
	var serial *big.Int
	var err error

	if len(args) == 0 {
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
		splitted = args
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
			return fmt.Errorf("Invalid serial number %s", sn)
		}

		err = cfg.DBBackend.DeleteCertificate(cfg, serial)
		if err != nil {
			return err
		}
	}

	return nil
}
