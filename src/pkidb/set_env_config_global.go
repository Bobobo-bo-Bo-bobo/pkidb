package main

import (
	"fmt"
	"strconv"
	"strings"
)

func setConfigurationGlobal(cfg *PKIConfiguration, key string, value string) error {
	switch key {
	case "auto_renew_start_period":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s: Can't convert %s to a number: %s", GetFrame(), value, err.Error())
		}
		cfg.Global.AutoRenewStartPeriod = int64(v)
	case "backend":
		cfg.Global.Backend = value
	case "ca_certificate":
		cfg.Global.CaCertificate = value
	case "ca_passphrase":
		cfg.Global.CaPassphrase = value
	case "ca_private_key":
		cfg.Global.CaPrivateKey = value
	case "ca_public_key":
		cfg.Global.CaPublicKey = value
	case "crl_certificate":
		cfg.Global.CrlCertificate = value
	case "crl_digest":
		cfg.Global.CrlDigest = value
	case "crl_passphrase":
		cfg.Global.CrlPassphrase = value
	case "crl_private_key":
		cfg.Global.CrlPrivateKey = value
	case "crl_public_key":
		cfg.Global.CrlPublicKey = value
	case "crl_validity_period":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s: Can't convert %s to a number: %s", GetFrame(), value, err.Error())
		}
		cfg.Global.CrlValidityPeriod = int(v)
	case "default_site":
		cfg.Global.DefaultSite = value
	case "digest":
		cfg.Global.Digest = value
	case "list_as_hex":
		lah := strings.TrimSpace(strings.ToLower(value))
		switch lah {
		case "1":
			fallthrough
		case "true":
			fallthrough
		case "yes":
			cfg.Global.ListAsHex = true
		case "0":
			fallthrough
		case "false":
			fallthrough
		case "no":
			cfg.Global.ListAsHex = false
		default:
			return fmt.Errorf("%s: Invalid value for PKIDB_GLOBAL_LIST_AS_HEX, use either 1/true/yes or 0/false/no", GetFrame())
		}
	case "serial_number":
		cfg.Global.SerialNumber = value
	case "sites":
		cfg.Global.Sites = value
	case "validity_period":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s: Can't convert %s to a number: %s", GetFrame(), value, err.Error())
		}
		cfg.Global.ValidityPeriod = int64(v)
	default:
		return fmt.Errorf("%s: Invalid or unknown configuration %s", GetFrame(), value)
	}

	return nil
}
