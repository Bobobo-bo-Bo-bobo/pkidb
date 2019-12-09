package main

import (
	"crypto/x509/pkix"
    "fmt"
)

// BuildX509Extension - build pkix.Extension
func BuildX509Extension(ext X509ExtensionData) (pkix.Extension, error) {
	var result pkix.Extension
	oid, err := StringToASN1ObjectIdentifier(ext.Name)
	if err != nil {
        return result, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	result.Id = oid
	result.Critical = ext.Critical
	result.Value = ext.Data
	return result, nil
}
