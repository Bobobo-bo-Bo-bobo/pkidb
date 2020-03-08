package main

import (
	"fmt"
	ini "gopkg.in/ini.v1"
	"strings"
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

	logging, err := cfg.GetSection("logging")
	if err == nil {
		keys := logging.KeyStrings()
		for _, k := range keys {
			key, err := logging.GetKey(k)
			if err != nil {
				continue
			}
			value := strings.TrimSpace(key.String())
			if value == "" {
				return nil, fmt.Errorf("%s: Invalid logging configuration %s=", GetFrame(), k)
			}
			ldo := strings.SplitN(value, ",", 2)

			level := ldo[0]
			if level == "" {
				return nil, fmt.Errorf("%s: Invalid logging configuration %s=%s", GetFrame(), k, value)
			}

			llevel, found := LogLevelMap[strings.ToLower(level)]
			if !found {
				return nil, fmt.Errorf("%s: Invalid log level %s", GetFrame(), level)
			}

			do := strings.SplitN(ldo[1], ":", 2)
			destination := strings.ToLower(do[0])
			option := do[1]
			if destination != "file" && destination != "syslog" {
				return nil, fmt.Errorf("%s: Invalid log destination %s", GetFrame(), destination)
			}

			l := LogConfiguration{
				Level:       level,
				Destination: destination,
				Option:      option,
				LogLevel:    llevel,
			}

			config.Logging = append(config.Logging, l)
		}
	}

	config.VaultToken = getVaultToken(&config)
	err = FetchDataCA(&config)
	if err != nil {
		return &config, err
	}
	err = FetchDataCRL(&config)
	if err != nil {
		return &config, err
	}
	err = FetchDataOCSP(&config)
	if err != nil {
		return &config, err
	}

	err = LoadSSLKeyPairs(&config)
	if err != nil {
		return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// [<database>]
	switch config.Global.Backend {
	case "mysql":
		db, err := cfg.GetSection(config.Global.Backend)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		err = db.MapTo(&dbconfig)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.Database = &dbconfig

		err = FetchDataDatabase(&config)
		if err != nil {
			return &config, err
		}

		var mysql PKIDBBackendMySQL
		err = mysql.Initialise(&config)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.DBBackend = mysql
	case "pgsql":
		db, err := cfg.GetSection(config.Global.Backend)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		err = db.MapTo(&dbconfig)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.Database = &dbconfig

		err = FetchDataDatabase(&config)
		if err != nil {
			return &config, err
		}

		var pgsql PKIDBBackendPgSQL
		err = pgsql.Initialise(&config)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.DBBackend = pgsql
	case "sqlite3":
		db, err := cfg.GetSection(config.Global.Backend)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		err = db.MapTo(&dbconfig)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.Database = &dbconfig

		err = FetchDataDatabase(&config)
		if err != nil {
			return &config, err
		}

		var sql3 PKIDBBackendSQLite3
		err = sql3.Initialise(&config)
		if err != nil {
			return &config, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		config.DBBackend = sql3
	case "":
		return &config, fmt.Errorf("%s: No database backend found in configuration file", GetFrame())

	default:
		return &config, fmt.Errorf("%s: Unknown database backend found in configuration file", GetFrame())
	}

	return &config, nil
}
