package main

import (
	"fmt"
)

func setConfiguration(cfg *PKIConfiguration, value string, envCfg EnvConfig) error {
	switch envCfg.Section {
	case "global":
		return setConfigurationGlobal(cfg, envCfg.ConfigKey, value)
	case "mysql":
		//
	case "pgsql":
		//
	case "sqlite3":
		//
	default:
		return fmt.Errorf("%s: Invalid configuration section %s", GetFrame(), envCfg.Section)
	}
	return nil
}
