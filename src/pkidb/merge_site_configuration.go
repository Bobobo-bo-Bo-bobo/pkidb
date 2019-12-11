package main

// MergeSiteConfiguration - merge global and site configuration
func MergeSiteConfiguration(gcfg *PKIConfiguration, scfg *PKIConfiguration) *PKIConfiguration {
	gdbcfg := *gcfg.Database

	ncfg := &PKIConfiguration{
		Global:   gcfg.Global,
		Database: &gdbcfg,
	}

	if scfg.Global.CaPublicKey != "" {
		ncfg.Global.CaPublicKey = scfg.Global.CaPublicKey
	}
	if scfg.Global.CaCertificate != "" {
		ncfg.Global.CaCertificate = scfg.Global.CaCertificate
	}

	if scfg.Global.CaPrivateKey != "" {
		ncfg.Global.CaPrivateKey = scfg.Global.CaPrivateKey
	}

	if scfg.Global.CaPassphrase != "" {
		ncfg.Global.CaPassphrase = scfg.Global.CaPassphrase
	}

	if scfg.Global.Digest != "" {
		ncfg.Global.Digest = scfg.Global.Digest
	}

	if scfg.Global.SerialNumber != "" {
		ncfg.Global.SerialNumber = scfg.Global.SerialNumber
	}

	if scfg.Global.ValidityPeriod != 0 {
		ncfg.Global.ValidityPeriod = scfg.Global.ValidityPeriod
	}

	if scfg.Global.AutoRenewStartPeriod != 0 {
		ncfg.Global.AutoRenewStartPeriod = scfg.Global.AutoRenewStartPeriod
	}

	if scfg.Global.CrlPublicKey != "" {
		ncfg.Global.CrlPublicKey = scfg.Global.CrlPublicKey
	}

	if scfg.Global.CrlCertificate != "" {
		ncfg.Global.CrlCertificate = scfg.Global.CrlCertificate
	}

	if scfg.Global.CrlPrivateKey != "" {
		ncfg.Global.CrlPrivateKey = scfg.Global.CrlPrivateKey
	}

	if scfg.Global.CrlPassphrase != "" {
		ncfg.Global.CrlPassphrase = scfg.Global.CrlPassphrase
	}

	if scfg.Global.CrlValidityPeriod != 0 {
		ncfg.Global.CrlValidityPeriod = scfg.Global.CrlValidityPeriod
	}

	if scfg.Global.CrlDigest != "" {
		ncfg.Global.CrlDigest = scfg.Global.CrlDigest
	}

	/*
		if scfg.Global.ListAsHex != "" {
			ncfg.Global.ListAsHex = scfg.Global.ListAsHex
		}
	*/
	if scfg.Global.Backend != "" {
		ncfg.Global.Backend = scfg.Global.Backend
	}

	if scfg.Database.Host != "" {
		ncfg.Database.Host = scfg.Database.Host
	}

	if scfg.Database.Port != 0 {
		ncfg.Database.Port = scfg.Database.Port
	}

	if scfg.Database.Database != "" {
		ncfg.Database.Database = scfg.Database.Database
	}

	if scfg.Database.User != "" {
		ncfg.Database.User = scfg.Database.User
	}

	if scfg.Database.Password != "" {
		ncfg.Database.Password = scfg.Database.Password
	}

	if scfg.Database.SSLCACert != "" {
		ncfg.Database.SSLCACert = scfg.Database.SSLCACert
	}

	if scfg.Database.SSLCert != "" {
		ncfg.Database.SSLCert = scfg.Database.SSLCert
	}

	if scfg.Database.SSLKey != "" {
		ncfg.Database.SSLKey = scfg.Database.SSLKey
	}

	if scfg.Database.SSLMode != "" {
		ncfg.Database.SSLMode = scfg.Database.SSLMode
	}

	return ncfg
}
