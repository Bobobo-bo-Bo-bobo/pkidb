package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// CmdBackup - export certificate
func CmdBackup(cfg *PKIConfiguration, args []string) error {
	var fd *os.File
	var err error

	argParse := flag.NewFlagSet("cmd-backup", flag.ExitOnError)
	var output = argParse.String("output", "", "Write backup to <output> instead of standard output")
	argParse.Parse(args)

	cmdBackupTrailing := argParse.Args()
	if len(cmdBackupTrailing) > 0 {
		return fmt.Errorf("Too many arguments")
	}

	dump, err := cfg.DBBackend.BackupToJSON(cfg)
	if err != nil {
		return err
	}

	data, err := json.Marshal(dump)
	if err != nil {
		return err
	}

	if *output == "" {
		fd = os.Stdout
	} else {
		fd, err = os.Create(*output)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprintf(fd, "%s", string(data))
	if err != nil {
		return err
	}
	if *output != "" {
		err = fd.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
