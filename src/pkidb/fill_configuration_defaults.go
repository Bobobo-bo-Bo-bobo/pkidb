package main

// FillConfigurationDefaults - set defaults
func FillConfigurationDefaults(cfg *PKIConfiguration) {
	if cfg.Global.Digest == "" {
		cfg.Global.Digest = "sha512"
	}

	if cfg.Global.SerialNumber == "" {
		cfg.Global.SerialNumber = "random"
	}

	if cfg.Global.ValidityPeriod == 0 {
		cfg.Global.ValidityPeriod = 1095
	}

	if cfg.Global.AutoRenewStartPeriod == 0 {
		cfg.Global.AutoRenewStartPeriod = 14
	}

	if cfg.Global.CrlValidityPeriod == 0 {
		cfg.Global.CrlValidityPeriod = 7
	}

	if cfg.Global.VaultTimeout == 0 {
		cfg.Global.VaultTimeout = 5
	}

	if cfg.Database != nil {
		if cfg.Database.Port == 0 {
			switch cfg.Global.Backend {
			case "mysql":
				cfg.Database.Port = 3306
			case "pgsql":
				cfg.Database.Port = 5432
			}
		}
		if cfg.Database.Host == "" {
			switch cfg.Global.Backend {
			case "mysql":
				fallthrough
			case "pgsql":
				cfg.Database.Host = "localhost"
			case "sqlite3":
				// not required
			}
		}
	}
}
