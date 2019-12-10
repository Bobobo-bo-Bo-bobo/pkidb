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
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// [global]
	global, err := cfg.GetSection("global")
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = global.MapTo(&config.Global)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// TODO: Parse logging information

	// TODO: Parse and handle site configuration

	// [<database>]
	switch config.Global.Backend {
	case "mysql":
		fallthrough
	case "pgsql":
		db, err := cfg.GetSection(config.Global.Backend)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		err = db.MapTo(&dbconfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.Database = &dbconfig
		var pgsql PKIDBBackendPgSQL
		err = pgsql.Initialise(&config)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.DBBackend = pgsql
	case "sqlite3":
		db, err := cfg.GetSection(config.Global.Backend)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		err = db.MapTo(&dbconfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.Database = &dbconfig
		var sql3 PKIDBBackendSQLite3
		err = sql3.Initialise(&config)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.DBBackend = sql3
	case "":
		return nil, fmt.Errorf("%s: No database backend found in configuration file", GetFrame())

	default:
		return nil, fmt.Errorf("%s: Unknown database backend found in configuration file", GetFrame())
	}

	err = LoadSSLKeyPairs(&config)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	return &config, nil
}
