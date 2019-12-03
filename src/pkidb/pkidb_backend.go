package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
)

// PKIDBBackend - Database backend
type PKIDBBackend interface {
	Initialise(*PKIConfiguration) error
	GetLastSerialNumber(*PKIConfiguration) (*big.Int, error)
	IsFreeSerialNumber(*PKIConfiguration, *big.Int) (bool, error)
	IsUsedSerialNumber(*PKIConfiguration, *big.Int) (bool, error)
	OpenDatabase(*PKIConfiguration) (*sql.DB, error)
	CloseDatabase(*sql.DB) error
	StoreCertificate(*PKIConfiguration, *ImportCertificate, bool) error
	StoreSignatureAlgorithm(*PKIConfiguration, x509.SignatureAlgorithm) (int, error)
	StoreSignatureAlgorithmName(*PKIConfiguration, string) (int, error)
	SerialNumberAlreadyPresent(*PKIConfiguration, *big.Int) (bool, error)
	StoreCertificateSigningRequest(*PKIConfiguration, *ImportCertificate) error
	StoreX509Extension(*PKIConfiguration, *ImportCertificate, []pkix.Extension) error
	StoreRevocation(*PKIConfiguration, *RevokeRequest) error
	StoreAutoRenew(*PKIConfiguration, *AutoRenew) error
}
