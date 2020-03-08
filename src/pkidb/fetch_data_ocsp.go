package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
)

// FetchDataOCSP - get data from Vault
func FetchDataOCSP(cfg *PKIConfiguration) error {
	var isv bool
	var u string
	var err error

	if cfg.Global.OcspPublicKey != "" {
		isv, u, err = isVaultURL(cfg.Global.OcspPublicKey)
		if err != nil {
			return err
		}
		if isv {
			vres, err := getDataFromVault(cfg, u)
			if err != nil {
				return err
			}

			if len(vres.Data.OcspPublicKey) != 0 {
				cfg.Global.ocspPublicKey = []byte(vres.Data.OcspPublicKey)
			}
		} else {
			cfg.Global.ocspPublicKey, err = ioutil.ReadFile(u)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	if cfg.Global.OcspCertificate != "" {
		isv, u, err = isVaultURL(cfg.Global.OcspCertificate)
		if err != nil {
			return err
		}
		if isv {
			vres, err := getDataFromVault(cfg, u)
			if err != nil {
				return err
			}

			if len(vres.Data.OcspPublicKey) != 0 {
				cfg.Global.ocspCertificate = []byte(vres.Data.OcspPublicKey)
			}
		} else {
			cfg.Global.ocspCertificate, err = ioutil.ReadFile(u)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	isv, u, err = isVaultURL(cfg.Global.OcspPrivateKey)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if len(vres.Data.OcspPrivateKey) != 0 {
			// PKCS8 is binary and MUST be base64 encoded - see: https://github.com/hashicorp/vault/issues/1423
			cfg.Global.ocspPrivateKey, err = base64.StdEncoding.DecodeString(string(vres.Data.OcspPrivateKey))
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	} else {
		cfg.Global.ocspPrivateKey, err = ioutil.ReadFile(u)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	// Passphrase is a special case because it can contain charactes (e.g. %) which will confuse url.Parse
	if strings.Index(cfg.Global.OcspPassphrase, "vault://") == 0 || strings.Index(cfg.Global.OcspPassphrase, "vaults://") == 0 || strings.Index(cfg.Global.OcspPassphrase, "http://") == 0 || strings.Index(cfg.Global.OcspPassphrase, "https://") == 0 {
		_, u, err = isVaultURL(cfg.Global.OcspPassphrase)
		if err != nil {
			return err
		}
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}
		cfg.Global.OcspPassphrase = string(vres.Data.OcspPassphrase)
	}

	return nil
}
