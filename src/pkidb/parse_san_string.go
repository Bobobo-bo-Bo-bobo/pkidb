package main

import (
	"fmt"
	"strings"
)

// ParseSANString - parse SAN string
func ParseSANString(san string) ([]X509SubjectAlternateNameData, error) {
	var result = make([]X509SubjectAlternateNameData, 0)
	for _, san := range strings.Split(san, ",") {
		_san := X509SubjectAlternateNameData{}
		rawSan := strings.Split(san, ":")
		if len(rawSan) == 2 {
			_san.Type = strings.ToLower(rawSan[0])
			_san.Value = rawSan[1]
		} else {
			return nil, fmt.Errorf("%s: Invalid subject alternate name option", GetFrame())
		}

		result = append(result, _san)
	}
	return result, nil
}
