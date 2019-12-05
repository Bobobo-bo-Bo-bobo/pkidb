package main

import (
	"crypto/x509"
	"database/sql"
	"math/big"
	"time"
)

// PKIConfiguration - Configuration
type PKIConfiguration struct {
	CAPublicKey   []byte
	CAPrivateKey  []byte
	Global        GlobalConfiguration
	Database      *DatabaseConfiguration
	CACertificate *x509.Certificate
	DBBackend     PKIDBBackend
}

// GlobalConfiguration - Global configration (section global from ini file)
type GlobalConfiguration struct {
	CaPublicKey          string `ini:"ca_public_key"`
	CaPrivateKey         string `ini:"ca_private_key"`
	CaPassphrase         string `ini:"ca_passphrase"`
	Digest               string `ini:"digest"`
	SerialNumber         string `ini:"serial_number"`
	ValidityPeriod       int    `ini:"validity_period"`
	AutoRenewStartPeriod int    `ini:"auto_renew_start_period"`
	CrlPublicKey         string `ini:"crl_public_key"`
	CrlPrivateKey        string `ini:"crl_private_key"`
	CrlPassphrase        string `ini:"crl_passphrase"`
	CrlValidtyPeriod     string `ini:"crl_validity_period"`
	CrlDigest            string `ini:"crl_digest"`
	ListAsHex            bool   `ini:"list_as_hex"`
	Backend              string `ini:"backend"`
	Sites                string `ini:"sites"`
	DefaultSite          string `ini:"default_site"`
}

// DatabaseConfiguration - Database configuration
type DatabaseConfiguration struct {
	Host      string `ini:"host"`
	Port      int    `ini:"port"`
	Database  string `ini:"database"`
	User      string `ini:"user"`
	Password  string `ini:"passphrase"`
	SSLCACert string `ini:"sslcacert"`
	SSLCert   string `ini:"sslcert"`
	SSLKey    string `ini:"sslkey"`
	SSLMode   string `ini:"sslmode"`
	dbhandle  *sql.DB
}

// EnvConfig - For mapping of environment variables to configuration settings
type EnvConfig struct {
	Section   string
	ConfigKey string
}

// X509ExtensionData - X509 extensions
type X509ExtensionData struct {
	Name     string
	Critical bool
	Data     []byte
}

// X509ExtendedKeyUsageData - X509 extended key usage
type X509ExtendedKeyUsageData struct {
	Critical bool
	Flags    string
}

// X509SubjectAlternateNameData - X509 SAN extension data
type X509SubjectAlternateNameData struct {
	Critical bool
	Type     string
	Value    string
}

// X509BasicConstraintData - X509 basic constraints
type X509BasicConstraintData struct {
	Critical bool
	Type     string
	Value    string
}

// X509KeyUsageData - X509 key usage
type X509KeyUsageData struct {
	Critical bool
	Type     string
}

// SignRequest - Information about CSR to be signed
type SignRequest struct {
	CSRData          []byte
	Extension        []X509ExtensionData
	ExtendedKeyUsage []X509ExtendedKeyUsageData
	SAN              []X509SubjectAlternateNameData
	BasicConstratint []X509BasicConstraintData
	KeyUsage         []X509KeyUsageData
	NoRegistration   bool
	NotBefore        time.Time
	NotAfter         time.Time
	AutoRenew        bool
}

// ImportCertificate - Import certificate
type ImportCertificate struct {
	Certificate    *x509.Certificate
	CSR            *x509.CertificateRequest
	AutoRenew      *AutoRenew
	Revoked        *RevokeRequest
	IsDummy        bool
	DummySubject   string
	DummyNotBefore *time.Time
	DummyNotAfter  *time.Time
}

// AutoRenew - auto renew certificates
type AutoRenew struct {
	SerialNumber *big.Int
	Delta        int // AutoRenewStartPeriod
	Period       int // ValidityPeriod
}

// RevokeRequest - Revocation request
type RevokeRequest struct {
	SerialNumber *big.Int
	Reason       string
	Time         time.Time
	Force        bool
}

// CertificateInformation - certificate information
type CertificateInformation struct {
	SerialNumber       *big.Int
	Version            int
	KeySize            int
	SignatureAlgorithm string
	State              string
	NotBefore          *time.Time
	NotAfter           *time.Time
	Subject            string
	Issuer             string
	FingerPrintMD5     string
	FingerPrintSHA1    string
	AutoRenewable      *AutoRenew
	Extensions         []X509ExtensionData
	PublicKey          string
	CSR                string
	Revoked            *RevokeRequest
}

// JSONInOutput - JSON format for backup/restore
type JSONInOutput struct {
	SigningRequests     []JSONSigningRequest     `json:"signing_request"`
	Extensions          []JSONExtension          `json:"extension"`
	Certificates        []JSONCertificate        `json:"certificate"`
	SignatureAlgorithms []JSONSignatureAlgorithm `json:"signature_algorithm"`
}

// JSONSignatureAlgorithm - "signature_algorithm" from JSON
type JSONSignatureAlgorithm struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
}

// JSONCertificate - "certificate" from JSON
type JSONCertificate struct {
	RevocationDate          *float64 `json:"revocation_date"`
	AutoRenewValidityPeriod *int     `json:"auto_renew_validity_period"`
	Certificate             string   `json:"certificate"`
	EndDate                 *int64   `json:"end_date"`
	AutoRenewStartPeriod    *int     `json:"auto_renew_start_period"`
	Extension               []string `json:"extension"`
	SignatureAlgorithmID    *int     `json:"signature_algorithm_id"`
	RevocationReason        *int     `json:"revocation_reason"`
	FingerPrintSHA1         *string  `json:"fingerprint_sha1"`
	AutoRenewable           bool     `json:"auto_renewable"`
	State                   int      `json:"state"`
	Version                 int      `json:"version"`
	SigningRequest          *string  `json:"signing_request"`
	KeySize                 int      `json:"keysize"`
	SerialNumber            string   `json:"serial_number"`
	FingerPrintMD5          *string  `json:"fingerprint_md5"`
	Issuer                  *string  `json:"issuer"`
	StartDate               *int64   `json:"start_date"`
	Subject                 string   `json:"subject"`
}

// JSONExtension - "extension" from JSON
type JSONExtension struct {
	Data     string `json:"data"`
	Critical bool   `json:"critical"`
	Hash     string `json:"hash"`
	Name     string `json:"name"`
}

// JSONSigningRequest - "signing_request" from JSON
type JSONSigningRequest struct {
	Request string `json:"request"`
	Hash    string `json:"hash"`
}
