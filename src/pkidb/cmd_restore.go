package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// CmdRestore - Restore from backup
func CmdRestore(cfg *PKIConfiguration, args []string) error {
	var restore JSONInOutput
	var data []byte
	var err error

	if len(args) > 1 {
		return fmt.Errorf("Too many arguments")
	}

	if len(args) == 0 {
		data, err = ioutil.ReadAll(os.Stdin)
	} else {
		data, err = ioutil.ReadFile(args[0])
	}
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &restore)
	if err != nil {
		return err
	}

	err = cfg.DBBackend.RestoreFromJSON(cfg, &restore)
	if err != nil {
		return err
	}

	return nil
}