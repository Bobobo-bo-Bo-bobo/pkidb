package main

import (
	"fmt"
	"strings"
)

// ParseBasicConstraintString - parse basic constraint string
func ParseBasicConstraintString(basicConstraint string) ([]X509BasicConstraintData, error) {
	var result = make([]X509BasicConstraintData, 0)

	for _, bcd := range strings.Split(basicConstraint, ",") {
		_bcd := X509BasicConstraintData{}
		rawBcd := strings.Split(bcd, ":")
		if len(rawBcd) == 2 {
			_bcd.Type = rawBcd[0]
			_bcd.Value = rawBcd[1]
		} else {
			return nil, fmt.Errorf("%s: Invalid basic constraint data", GetFrame())
		}
		result = append(result, _bcd)
	}
	return result, nil
}
