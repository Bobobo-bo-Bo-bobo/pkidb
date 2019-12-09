package main

import (
	"flag"
	"fmt"
)

// CmdStatistics - show statistics
func CmdStatistics(cfg *PKIConfiguration, args []string) error {

	argParse := flag.NewFlagSet("cmd-statitstics", flag.ExitOnError)
	argParse.Usage = showHelpStatistics
	argParse.Parse(args)

	cmdStatisticsTrailing := argParse.Args()
	if len(cmdStatisticsTrailing) != 0 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	stats, err := cfg.DBBackend.GetStatistics(cfg)
	if err != nil {
		return err
	}

	for key1, value1 := range stats {
		for key2, value2 := range value1 {
			fmt.Printf("%s:%s:%d\n", key1, key2, value2)
		}
	}

	return nil
}
