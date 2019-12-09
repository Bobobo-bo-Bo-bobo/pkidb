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
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("No certificate with serial number %s found in database", serial.Text(10))
	}

	pb, _ := pem.Decode(cert)
	if pb == nil {
		return nil, fmt.Errorf("Can't decode certificate from database")
	}

	oldCert, err := x509.ParseCertificate(pb.Bytes)
	if err != nil {
		return nil, err
	}

	if oldCert.NotBefore.After(newEnd) {
		return nil, fmt.Errorf("New end date is before start date")
	}

	oldCert.NotAfter = newEnd

	newCert, err := x509.CreateCertificate(rand.Reader, oldCert, cfg.CAPublicKey, oldCert.PublicKey, cfg.CACertificate.PrivateKey)
	if err != nil {
		return nil, err
	}

	return newCert, nil
}
