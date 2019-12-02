package main

import (
	"crypto/x509"
	"time"
)

// GetCertificateState - Get status of a certificate
func GetCertificateState(cert *x509.Certificate) int {
	now := time.Now()

	if cert.NotBefore.After(now) {
		return PKICertificateStatusInvalid
	}
	if cert.NotAfter.Before(now) {
		return PKICertificateStatusExpired
	}
	return PKICertificateStatusValid
}
