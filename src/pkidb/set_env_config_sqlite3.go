package main

import (
	"fmt"
)

func setConfigurationSQLite3(cfg *PKIConfiguration, key string, value string) error {
	switch key {
	case "database":
		cfg.Database.Database = value
	default:
		return fmt.Errorf("%s: Invalid or unknown configuration %s", GetFrame(), value)
	}

	return nil
}
