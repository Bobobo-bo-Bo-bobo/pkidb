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
	DeleteCertificate(*PKIConfiguration, *big.Int) error
	CertificateInformation(*PKIConfiguration, *big.Int) (*CertificateInformation, error)
	GetSignatureAlgorithmName(*PKIConfiguration, int) (string, error)
	GetCertificateSigningRequest(*PKIConfiguration, string) (string, error)
	GetX509Extension(*PKIConfiguration, string) (X509ExtensionData, error)
	SearchSubject(*PKIConfiguration, string) (*big.Int, error)
	RestoreFromJSON(*PKIConfiguration, *JSONInOutput) error
	BackupToJSON(*PKIConfiguration) (*JSONInOutput, error)
	GetSerialNumbersByState(*PKIConfiguration, int) ([]*big.Int, error)
	LockSerialNumber(*PKIConfiguration, *big.Int, int, bool) error
}
