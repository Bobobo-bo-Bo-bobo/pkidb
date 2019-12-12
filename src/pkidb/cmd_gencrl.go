package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

// CmdGenCRL - generate CRL
func CmdGenCRL(cfg *PKIConfiguration, args []string) error {
	var err error
	var fd *os.File

	argParse := flag.NewFlagSet("cmd-gencrl", flag.ExitOnError)
	var output = argParse.String("output", "", "Write revocation list to <output> instead of standard output")
	argParse.Usage = showHelpGenCRL
	argParse.Parse(args)

	cmdGenCRLTrailing := argParse.Args()
	if len(cmdGenCRLTrailing) != 0 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	crl, err := GenerateCRL(cfg)
	if err != nil {
		return err
	}

	if *output != "" {
		fd, err = os.Create(*output)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	} else {
		fd = os.Stdout
	}

	err = pem.Encode(fd, &pem.Block{Type: "X509 CRL", Bytes: crl})
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if *output != "" {
		err = fd.Close()
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	LogMessage(cfg, LogLevelInfo, "Certificate revocation list created")
	return nil
}
