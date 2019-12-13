package main

import (
	"fmt"
)

// ValidateConfiguration - validate configuration
func ValidateConfiguration(cfg *PKIConfiguration) error {
	if cfg.Global.CaCertificate != "" {
		if cfg.Global.CaPublicKey == "" {
			cfg.Global.CaPublicKey = cfg.Global.CaCertificate
		} else {
			return fmt.Errorf("%s: Set either ca_certificate or ca_public_key but not both", GetFrame())
		}
	}
	if (cfg.Global.CaPublicKey != "" && cfg.Global.CaPrivateKey == "") || (cfg.Global.CaPublicKey == "" && cfg.Global.CaPrivateKey != "") {
		return fmt.Errorf("%s: If set both ca_public_key and ca_private_key must be defined", GetFrame())
	}

	if cfg.Global.CrlCertificate != "" {
		if cfg.Global.CrlPublicKey == "" {
			cfg.Global.CrlPublicKey = cfg.Global.CrlCertificate
		} else {
			return fmt.Errorf("%s: Set either crl_certificate or crl_public_key but not both", GetFrame())
		}
	}
	if (cfg.Global.CrlPublicKey != "" && cfg.Global.CrlPrivateKey == "") || (cfg.Global.CrlPublicKey == "" && cfg.Global.CrlPrivateKey != "") {
		return fmt.Errorf("%s: If set both crl_public_key and crl_private_key must be defined", GetFrame())
	}

	if cfg.Global.CaPrivateKey != "" && cfg.Global.CaPassphrase == "" {
		return fmt.Errorf("%s: Private key for signing CA must be encrypted", GetFrame())
	}

	if cfg.Global.CrlPrivateKey != "" && cfg.Global.CrlPassphrase == "" {
		return fmt.Errorf("%s: Private key for CRL signing must be encrypted", GetFrame())
	}

	if cfg.Database == nil {
		return fmt.Errorf("%s: No database defined", GetFrame())
	}

	if cfg.Global.ValidityPeriod <= 0 {
		return fmt.Errorf("%s: validity_period must be > 0", GetFrame())
	}

	if cfg.Global.AutoRenewStartPeriod <= 0 {
		return fmt.Errorf("%s: auto_renew_start_period must be > 0", GetFrame())
	}

	if cfg.Database.Port <= 0 || cfg.Database.Port > 65535 {
		return fmt.Errorf("%s: Invalid database port", GetFrame())
	}

	return nil
}
