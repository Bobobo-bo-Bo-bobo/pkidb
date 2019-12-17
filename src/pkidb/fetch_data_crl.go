package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
)

// FetchDataCRL - get data from Vault
func FetchDataCRL(cfg *PKIConfiguration) error {
	var isv bool
	var u string
	var err error

	if cfg.Global.CrlPublicKey != "" {
		isv, u, err = isVaultURL(cfg.Global.CrlPublicKey)
		if err != nil {
			return err
		}
		if isv {
			vres, err := getDataFromVault(cfg, u)
			if err != nil {
				return err
			}

			if len(vres.Data.CrlPublicKey) != 0 {
				cfg.Global.crlPublicKey = []byte(vres.Data.CrlPublicKey)
			}
		} else {
			cfg.Global.crlPublicKey, err = ioutil.ReadFile(u)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	if cfg.Global.CrlCertificate != "" {
		isv, u, err = isVaultURL(cfg.Global.CrlCertificate)
		if err != nil {
			return err
		}
		if isv {
			vres, err := getDataFromVault(cfg, u)
			if err != nil {
				return err
			}

			if len(vres.Data.CrlPublicKey) != 0 {
				cfg.Global.crlCertificate = []byte(vres.Data.CrlPublicKey)
			}
		} else {
			cfg.Global.crlCertificate, err = ioutil.ReadFile(u)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	isv, u, err = isVaultURL(cfg.Global.CrlPrivateKey)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if len(vres.Data.CrlPrivateKey) != 0 {
			// PKCS8 is binary and MUST be base64 encoded - see: https://github.com/hashicorp/vault/issues/1423
			cfg.Global.crlPrivateKey, err = base64.StdEncoding.DecodeString(string(vres.Data.CrlPrivateKey))
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	} else {
		cfg.Global.crlPrivateKey, err = ioutil.ReadFile(u)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	// Passphrase is a special case because it can contain charactes (e.g. %) which will confuse url.Parse
	if strings.Index(cfg.Global.CrlPassphrase, "vault://") == 0 || strings.Index(cfg.Global.CrlPassphrase, "vaults://") == 0 || strings.Index(cfg.Global.CrlPassphrase, "http://") == 0 || strings.Index(cfg.Global.CrlPassphrase, "https://") == 0 {
		_, u, err = isVaultURL(cfg.Global.CrlPassphrase)
		if err != nil {
			return err
		}
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}
		cfg.Global.CrlPassphrase = string(vres.Data.CrlPassphrase)
	}

	return nil
}
