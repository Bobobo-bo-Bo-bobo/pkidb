package main

import (
	"strings"
)

// FetchDataDatabase - get data from Vault
func FetchDataDatabase(cfg *PKIConfiguration) error {
	var u string
	var err error

	if cfg.Database == nil {
		return nil
	}
	// Password is a special case because it can contain charactes (e.g. %) which will confuse url.Parse
	if strings.Index(cfg.Database.Password, "vault://") == 0 || strings.Index(cfg.Database.Password, "vaults://") == 0 || strings.Index(cfg.Database.Password, "http://") == 0 || strings.Index(cfg.Database.Password, "https://") == 0 {
		_, u, err = isVaultURL(cfg.Database.Password)
		if err != nil {
			return err
		}
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}
		cfg.Database.Password = string(vres.Data.DatabasePassphrase)
	}

	return nil
}
