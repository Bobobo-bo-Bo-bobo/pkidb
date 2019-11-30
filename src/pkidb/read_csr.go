package main

import (
	"crypto/x509"
	"encoding/pem"
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
		return nil, err
	}

	_csr, _ := pem.Decode(rawCSR)
	csr, err := x509.ParseCertificateRequest(_csr.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}
