package main

import (
	"fmt"
	"strings"
)

// LoadSiteConfigurations - Load site configuration
func LoadSiteConfigurations(sites string) (map[string]*PKIConfiguration, error) {
	var result = make(map[string]*PKIConfiguration)

	if sites == "" {
		return result, nil
	}

	siteList := strings.Split(sites, " ")
	for _, sl := range siteList {
		if sl == "" {
			continue
		}

		nf := strings.SplitN(sl, ":", 2)
		if len(nf) != 2 || nf[1] == "" {
			return nil, fmt.Errorf("%s: Invalid site configuration %s", GetFrame(), sl)
		}
		name := nf[0]
		config, err := ParseConfiguration(nf[1])
		if err != nil {
			return nil, err
		}
		result[name] = config
	}
	return result, nil
}
