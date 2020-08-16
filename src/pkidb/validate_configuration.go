package main

import (
	"fmt"
)

// ValidateConfiguration - validate configuration
func ValidateConfiguration(cfg *PKIConfiguration) error {
	if len(cfg.Global.caCertificate) != 0 {
		if len(cfg.Global.caPublicKey) == 0 {
			cfg.Global.caPublicKey = cfg.Global.caCertificate
		} else {
			return fmt.Errorf("%s: Set either ca_certificate or ca_public_key but not both", GetFrame())
		}
	}
	if (len(cfg.Global.caPublicKey) != 0 && len(cfg.Global.caPrivateKey) == 0) || (len(cfg.Global.caPublicKey) == 0 && len(cfg.Global.caPrivateKey) != 0) {
		return fmt.Errorf("%s: If set both ca_public_key and ca_private_key must be defined", GetFrame())
	}

	if len(cfg.Global.crlCertificate) != 0 {
		if len(cfg.Global.crlPublicKey) == 0 {
			cfg.Global.crlPublicKey = cfg.Global.crlCertificate
		} else {
			return fmt.Errorf("%s: Set either crl_certificate or crl_public_key but not both", GetFrame())
		}
	}
	if (len(cfg.Global.crlPublicKey) != 0 && len(cfg.Global.crlPrivateKey) == 0) || (len(cfg.Global.crlPublicKey) == 0 && len(cfg.Global.crlPrivateKey) != 0) {
		return fmt.Errorf("%s: If set both crl_public_key and crl_private_key must be defined", GetFrame())
	}

	if len(cfg.Global.caPrivateKey) != 0 && cfg.Global.CaPassphrase == "" {
		return fmt.Errorf("%s: Private key for signing CA must be encrypted", GetFrame())
	}

	if len(cfg.Global.crlPrivateKey) != 0 && cfg.Global.CrlPassphrase == "" {
		return fmt.Errorf("%s: Private key for CRL signing must be encrypted", GetFrame())
	}

	if cfg.Global.VaultTimeout <= 0 {
		return fmt.Errorf("%s: Vault connection timeout must be greater than 0", GetFrame())
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

	if cfg.Global.Backend != "sqlite3" {
		if cfg.Database.Port <= 0 || cfg.Database.Port > 65535 {
			return fmt.Errorf("%s: Invalid database port", GetFrame())
		}
	}

	_, found := DigestHashMap[cfg.Global.OcspDigest]
	if !found {
		return fmt.Errorf("%s: Invalid OCSP digest", GetFrame())
	}

	return nil
}
