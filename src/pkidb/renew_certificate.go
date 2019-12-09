package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// RenewCertificate - renew certificate
func RenewCertificate(cfg *PKIConfiguration, serial *big.Int, newEnd time.Time) ([]byte, error) {
	cert, err := cfg.DBBackend.GetCertificate(cfg, serial)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	if cert == nil {
		return nil, fmt.Errorf("%s: No certificate with serial number %s found in database", GetFrame(), serial.Text(10))
	}

	pb, _ := pem.Decode(cert)
	if pb == nil {
		return nil, fmt.Errorf("%s: Can't decode certificate from database", GetFrame())
	}

	oldCert, err := x509.ParseCertificate(pb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if oldCert.NotBefore.After(newEnd) {
		return nil, fmt.Errorf("%s: New end date is before start date", GetFrame())
	}

	oldCert.NotAfter = newEnd

	newCert, err := x509.CreateCertificate(rand.Reader, oldCert, cfg.CAPublicKey, oldCert.PublicKey, cfg.CACertificate.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	return newCert, nil
}
