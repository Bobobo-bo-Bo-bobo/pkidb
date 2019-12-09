package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// ReadCSR - Read certificate signing request from a file
// Parameter:
//  csrFile - string, name of CSR file, if csrFile is empty stdin is used instead
//
// Return:
//  *x509.CertificateRequest - PKCS #10, certificate signature request
//  err                      - error
func ReadCSR(csrFile string) (*x509.CertificateRequest, error) {
	var rawCSR []byte
	var err error

	if csrFile == "" {
		rawCSR, err = ioutil.ReadAll(os.Stdin)
	} else {
		rawCSR, err = ioutil.ReadFile(csrFile)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if rawCSR == nil {
		return nil, fmt.Errorf("%s: No certificate signing request data found", GetFrame())
	}

	_csr, _ := pem.Decode(rawCSR)
	if _csr == nil {
		return nil, fmt.Errorf("%s: Can't decode provided data into signing request", GetFrame())
	}

	csr, err := x509.ParseCertificateRequest(_csr.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	return csr, nil
}
