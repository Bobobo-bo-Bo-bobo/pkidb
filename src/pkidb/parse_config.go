package main

import (
	"fmt"
	ini "gopkg.in/ini.v1"
)

// ParseConfiguration - Parse configuration file
func ParseConfiguration(file string) (*PKIConfiguration, error) {
	var config PKIConfiguration
	var dbconfig DatabaseConfiguration

	cfg, err := ini.LoadSources(ini.LoadOptions{IgnoreInlineComment: true}, file)
	if err != nil {
		return nil, err
	}

	// [global]
	global, err := cfg.GetSection("global")
	if err != nil {
		return nil, err
	}

	err = global.MapTo(&config.Global)
	if err != nil {
		return nil, err
	}

	// TODO: Parse logging information

	// TODO: Parse and handle site configuration

	// [<database>]
	switch config.Global.Backend {
	case "mysql":
		fallthrough
	case "pgsql":
		fallthrough
	case "sqlite3":
		db, err := cfg.GetSection(config.Global.Backend)
		if err != nil {
			return nil, err
		}

		err = db.MapTo(&dbconfig)
		if err != nil {
			return nil, err
		}
		config.Database = &dbconfig
		var sql3 PKIDBBackendSQLite3
		err = sql3.Initialise(&config)
		if err != nil {
			return nil, err
		}
		config.DBBackend = sql3
	case "":
		return nil, fmt.Errorf("No database backend found in configuration file")

	default:
		return nil, fmt.Errorf("Unknown database backend found in configuration file")
	}
	return &config, nil
}
