package main

import (
	"crypto/x509"
	"database/sql"
	"math/big"
)

// PKIDBBackend - Database backend
type PKIDBBackend interface {
	Initialise(*PKIConfiguration) error
	GetLastSerialNumber(*PKIConfiguration) (*big.Int, error)
	OpenDatabase(*PKIConfiguration) (*sql.DB, error)
	CloseDatabase(*sql.DB) error
	StoreCertificate(*PKIConfiguration, *ImportCertificate, bool) error
	StoreSignatureAlgorithm(*PKIConfiguration, x509.SignatureAlgorithm) (int, error)
	StoreSignatureAlgorithmName(*PKIConfiguration, string) (int, error)
	SerialNumberAlreadyPresent(*PKIConfiguration, *big.Int) (bool, error)
	StoreCertificateSigningRequest(*PKIConfiguration, *x509.CertificateRequest) error
}
