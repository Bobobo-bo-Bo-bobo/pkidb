package main

import (
	"strings"
)

// ParseKeyUsageString - parse key usage string
func ParseKeyUsageString(keyUsage string) ([]X509KeyUsageData, error) {
	var result = make([]X509KeyUsageData, 0)
	for _, kus := range strings.Split(keyUsage, ",") {
		_kus := X509KeyUsageData{}
		_kus.Type = kus
		_kus.Critical = true
		result = append(result, _kus)
	}
	return result, nil
}
