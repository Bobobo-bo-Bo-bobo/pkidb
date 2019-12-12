package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

// CmdRestore - Restore from backup
func CmdRestore(cfg *PKIConfiguration, args []string) error {
	var restore JSONInOutput
	var data []byte
	var err error

	argParse := flag.NewFlagSet("cmd-restore", flag.ExitOnError)
	argParse.Usage = showHelpRestore
	argParse.Parse(args)

	if len(args) > 1 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	if len(args) == 0 {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = json.Unmarshal(data, &restore)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = cfg.DBBackend.RestoreFromJSON(cfg, &restore)
	if err != nil {
		return err
	}

	LogMessage(cfg, LogLevelInfo, "Database dump restored")
	return nil
}
