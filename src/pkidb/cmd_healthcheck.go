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

	if *fix {
	}

	return nil
}
