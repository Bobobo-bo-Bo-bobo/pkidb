package main

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// StringToASN1ObjectIdentifier - convert OID string to ASN1 ObjectIdentifier
func StringToASN1ObjectIdentifier(s string) (asn1.ObjectIdentifier, error) {
	var oi asn1.ObjectIdentifier

	for i, sub := range strings.Split(s, ".") {
		// a leading dot is ok
		if sub == "" && i == 0 {
			continue
		}
		if sub == "" {
			return nil, fmt.Errorf("Invalid OID representation")
		}
		oid, err := strconv.Atoi(sub)
		if err != nil {
			return nil, err
		}
		oi = append(oi, oid)
	}
	return oi, nil
}
