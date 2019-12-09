package main

import (
	"flag"
	"fmt"
)

// CmdHousekeeping - housekeeping command
func CmdHousekeeping(cfg *PKIConfiguration, args []string) error {
	argParse := flag.NewFlagSet("cmd-housekeeping", flag.ExitOnError)
	var autoRenew = argParse.Bool("auto-renew", false, "Renew auto renewable certificates that will expire")
	var period = argParse.Int("period", 0, "Default is the value given on import that has been stored in the backend")
	argParse.Usage = showHelpHousekeeping
	argParse.Parse(args)

	cmdHousekeepingTrailing := argParse.Args()

	if len(cmdHousekeepingTrailing) != 0 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	if *period > 0 {
		*autoRenew = true
	}
	if *period < 0 {
		return fmt.Errorf("%s: period must be positive", GetFrame())
	}

	err := cfg.DBBackend.Housekeeping(cfg, *autoRenew, *period)
	if err != nil {
		return err
	}
	return nil
}
