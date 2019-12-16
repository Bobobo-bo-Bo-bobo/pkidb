package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
)

// VaultGet - get data from Vault
func VaultGet(cfg *PKIConfiguration) error {
	// CA data
	isv, u, err := isVaultURL(cfg.Global.CaPublicKey)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.CaPublicKey != nil {
			cfg.Global.CaPublicKey = *vres.Data.CaPublicKey
		}
	}

	isv, u, err = isVaultURL(cfg.Global.CaCertificate)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.CaPublicKey != nil {
			cfg.Global.CaCertificate = *vres.Data.CaPublicKey
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

		if vres.Data.CaPrivateKey != nil {
			// PKCS8 is binary and MUST be base64 encoded - see: https://github.com/hashicorp/vault/issues/1423
			decoded, err := base64.StdEncoding.DecodeString(*vres.Data.CaPrivateKey)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			cfg.Global.CaPrivateKey = string(decoded)
		}
	}

	isv, u, err = isVaultURL(cfg.Global.CaPassphrase)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.CaPassphrase != nil {
			cfg.Global.CaPassphrase = *vres.Data.CaPassphrase
		}
	}

	// CRL data
	isv, u, err = isVaultURL(cfg.Global.CrlPublicKey)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.CrlPublicKey != nil {
			cfg.Global.CrlPublicKey = *vres.Data.CrlPublicKey
		}
	}

	isv, u, err = isVaultURL(cfg.Global.CrlCertificate)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.CrlPublicKey != nil {
			cfg.Global.CrlCertificate = *vres.Data.CrlPublicKey
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

		if vres.Data.CrlPrivateKey != nil {
			// PKCS8 is binary and MUST be base64 encoded - see: https://github.com/hashicorp/vault/issues/1423
			decoded, err := base64.StdEncoding.DecodeString(*vres.Data.CrlPrivateKey)
			if err != nil {
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			cfg.Global.CrlPrivateKey = string(decoded)
		}
	}

	isv, u, err = isVaultURL(cfg.Global.CrlPassphrase)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.CrlPassphrase != nil {
			cfg.Global.CrlPassphrase = *vres.Data.CrlPassphrase
		}
	}

	// Database data
	isv, u, err = isVaultURL(cfg.Database.SSLCert)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.DatabaseSSLCert != nil {
			cfg.Database.SSLCert = *vres.Data.DatabaseSSLCert
		}
	}

	isv, u, err = isVaultURL(cfg.Global.CrlCertificate)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.DatabaseSSLCert != nil {
			cfg.Global.CrlCertificate = *vres.Data.DatabaseSSLCert
		}
	}

	isv, u, err = isVaultURL(cfg.Database.SSLKey)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.DatabaseSSLKey != nil {
			cfg.Database.SSLKey = *vres.Data.DatabaseSSLKey
		}
	}

	isv, u, err = isVaultURL(cfg.Database.SSLCACert)
	if err != nil {
		return err
	}
	if isv {
		vres, err := getDataFromVault(cfg, u)
		if err != nil {
			return err
		}

		if vres.Data.DatabaseSSLCa != nil {
			cfg.Database.SSLCACert = *vres.Data.DatabaseSSLCa
		}
	}
	return nil
}

func getVaultToken(cfg *PKIConfiguration) string {
	// try environment variable VAULT_TOKEN first
	env := GetEnvironment()
	vlt, found := env["VAULT_TOKEN"]
	if found {
		return vlt
	}

	// if HOME is set, try to read ${HOME}/
	home, found := env["HOME"]
	if found {
		content, err := ioutil.ReadFile(filepath.Join(home, ".vault-token"))
		if err != nil {
			LogMessage(cfg, LogLevelWarning, fmt.Sprintf("%s: Can't read %s: %s", GetFrame(), filepath.Join(home, ".vault-token"), err.Error()))
			return ""
		}
		return string(content)
	}

	return ""
}

func getDataFromVault(cfg *PKIConfiguration, u string) (*VaultKVResult, error) {
	var vkvrslt VaultKVResult

	result, err := httpRequest(cfg, u, "GET", nil, nil)
	if err != nil {
		return nil, err
	}

	if result.StatusCode != 200 {
		return nil, fmt.Errorf("%s: Unexpected HTTP status, expected \"200 OK\" but got \"%s\" instead", GetFrame(), result.Status)
	}

	err = json.Unmarshal(result.Content, &vkvrslt)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	return &vkvrslt, nil
}

func isVaultURL(s string) (bool, string, error) {
	parsed, err := url.Parse(s)
	if err != nil {
		return false, "", fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	switch parsed.Scheme {
	case "http":
		fallthrough
	case "vault":
		return true, fmt.Sprintf("http://%s/%s", parsed.Host, parsed.Path), nil

	case "https":
		fallthrough
	case "vaults":
		return true, fmt.Sprintf("https://%s/%s", parsed.Host, parsed.Path), nil

	case "":
		return false, parsed.Path, nil

	default:
		return false, "", fmt.Errorf("%s: Unrecognized URL scheme %s", GetFrame(), parsed.Scheme)
	}

}
