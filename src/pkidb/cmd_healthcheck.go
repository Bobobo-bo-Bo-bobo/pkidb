package main

import (
	"flag"
	"fmt"
)

// CmdHealthcheck - healthcheck
func CmdHealthcheck(cfg *PKIConfiguration, args []string) error {
	argParse := flag.NewFlagSet("cmd-healthcheck", flag.ExitOnError)
	var fix = argParse.Bool("fix", false, "Fix errors")
	argParse.Usage = showHelpHealthcheck
	argParse.Parse(args)

	cmdHealthcheckTrailing := argParse.Args()
	if len(cmdHealthcheckTrailing) != 0 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

    // Note: To avoid parsing errors we don't do anything until this bug
    //       has been fixed:
    //          encoding/asn1: valid GeneralizedTime not parsed #15842 (https://github.com/golang/go/issues/15842)
	if *fix {
	}

	return nil
}
