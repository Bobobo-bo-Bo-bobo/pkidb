package main

import (
	"golang.org/x/crypto/ocsp"
)

func parseOCSPRequest(raw []byte) (*ocsp.Request, error) {
	result, err := ocsp.ParseRequest(raw)
	if err != nil {
		return nil, err
	}

	return result, nil
}
