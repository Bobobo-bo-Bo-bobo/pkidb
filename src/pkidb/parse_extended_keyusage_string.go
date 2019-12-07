package main

import (
	"strings"
)

// ParseExtendedKeyUsageString - parse extended key usage string
func ParseExtendedKeyUsageString(extendedKeyUsage string) ([]X509ExtendedKeyUsageData, error) {
	var result = make([]X509ExtendedKeyUsageData, 0)

	for _, eku := range strings.Split(extendedKeyUsage, ",") {
		ekud := X509ExtendedKeyUsageData{}
		ekud.Critical = false
		ekud.Flags = eku
		result = append(result, ekud)
	}
	return result, nil
}
