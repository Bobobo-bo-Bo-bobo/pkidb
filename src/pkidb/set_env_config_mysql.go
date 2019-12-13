package main

import (
	"fmt"
	"strconv"
)

func setConfigurationMySQL(cfg *PKIConfiguration, key string, value string) error {
	switch key {
	case "database":
		cfg.Database.Database = value
	case "host":
		cfg.Database.Host = value
	case "passphrase":
		cfg.Database.Password = value
	case "port":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s: Can't convert %s to a number: %s", GetFrame(), value, err.Error())
		}
		cfg.Database.Port = v
	case "sslcacert":
		cfg.Database.SSLCACert = value
	case "sslcert":
		cfg.Database.SSLCert = value
	case "sslkey":
		cfg.Database.SSLKey = value
	case "sslmode":
		cfg.Database.SSLMode = value
	case "user":
		cfg.Database.User = value
	default:
		return fmt.Errorf("%s: Invalid or unknown configuration %s", GetFrame(), value)
	}

	return nil
}
