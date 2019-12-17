package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
)

// FetchDataCA - get data from Vault
func FetchDataCA(cfg *PKIConfiguration) error {
	var isv bool
	var u string
	var err error

	if cfg.Global.CaPublicKey != "" {
		isv, u, err = isVaultURL(cfg.Global.CaPublicKey)
		if err != nil {
			return err
		}
		if isv {
			vres, err := getDataFromVault(cfg, u)
			if err != nil {
				return err
			}

			if len(vres.Data.CaPublicKey) != 0 {
				cfg.Global.caPublicKey = []byte(vres.Data.CaPublicKey)
			}
		} else {
			cfg.Global.caPublicKey, err = ioutil.ReadFile(u)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	if cfg.Global.CaCertificate != "" {
		isv, u, err = isVaultURL(cfg.Global.CaCertificate)
		if err != nil {
			return err
		}
		if isv {
			vres, err := getDataFromVault(cfg, u)
			if err != nil {
				return err
			}

			if len(vres.Data.CaPublicKey) != 0 {
				cfg.Global.caCertificate = []byte(vres.Data.CaPublicKey)
			}
		} else {
			cfg.Global.caCertificate, err = ioutil.ReadFile(u)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	isv, u, err = isVaultURL(cfg.Global.CaPrivateKey)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if len(vres.Data.CaPrivateKey) != 0 {
			// PKCS8 is binary and MUST be base64 encoded - see: https://github.com/hashicorp/vault/issues/1423
			cfg.Global.caPrivateKey, err = base64.StdEncoding.DecodeString(string(vres.Data.CaPrivateKey))
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	} else {
		cfg.Global.caPrivateKey, err = ioutil.ReadFile(u)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	// Passphrase is a special case because it can contain charactes (e.g. %) which will confuse url.Parse
	if strings.Index(cfg.Global.CaPassphrase, "vault://") == 0 || strings.Index(cfg.Global.CaPassphrase, "vaults://") == 0 || strings.Index(cfg.Global.CaPassphrase, "http://") == 0 || strings.Index(cfg.Global.CaPassphrase, "https://") == 0 {
		_, u, err = isVaultURL(cfg.Global.CaPassphrase)
		if err != nil {
			return err
		}
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}
		cfg.Global.CaPassphrase = string(vres.Data.CaPassphrase)
	}

	return nil
}
