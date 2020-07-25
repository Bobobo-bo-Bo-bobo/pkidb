package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
)

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
			if os.IsNotExist(err) {
				return ""
			}
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

	switch result.StatusCode {
	case 200:
		break
	case 403:
		return nil, fmt.Errorf("%s: Access denied (\"%s\") from Vault server. Are the token and/or the permissions to access %s valid?", GetFrame(), result.Status, u)
	case 404:
		return nil, fmt.Errorf("%s: Not found (\"%s\") from Vault server while accessing %s", GetFrame(), result.Status, u)
	default:
		return nil, fmt.Errorf("%s: Unexpected HTTP status, expected \"200 OK\" but got \"%s\" from %s instead", GetFrame(), u, result.Status)
	}

	err = json.Unmarshal(result.Content, &vkvrslt)
	if err != nil {
		return nil, fmt.Errorf("%s: %s (processing data from %s)", GetFrame(), err.Error(), u)
	}

	return &vkvrslt, nil
}

func isVaultURL(s string) (bool, string, error) {
	if s == "" {
		return false, "", nil
	}

	parsed, err := url.Parse(s)
	if err != nil {
		return false, "", fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	switch parsed.Scheme {
	case "http":
		fallthrough
	case "vault":
		if parsed.Path[len(parsed.Path)-1] == '/' {
			return false, "", fmt.Errorf("%s: Invalid vault location. Location can't end with /", GetFrame())
		}
		return true, fmt.Sprintf("http://%s/v1%s", parsed.Host, parsed.Path), nil

	case "https":
		fallthrough
	case "vaults":
		if parsed.Path[len(parsed.Path)-1] == '/' {
			return false, "", fmt.Errorf("%s: Invalid vault location. Location can't end with /", GetFrame())
		}
		return true, fmt.Sprintf("https://%s/v1%s", parsed.Host, parsed.Path), nil

	case "":
		return false, parsed.Path, nil

	default:
		return false, "", fmt.Errorf("%s: Unrecognized URL scheme %s", GetFrame(), parsed.Scheme)
	}

}
