package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"math/big"
	"net/http"
	"time"
)

// PKIConfiguration - Configuration
type PKIConfiguration struct {
	CAPublicKey     *x509.Certificate
	CACertificate   *tls.Certificate
	CRLPublicKey    *x509.Certificate
	CRLCertificate  *tls.Certificate
	OCSPPublicKey   *x509.Certificate
	OCSPCertificate *tls.Certificate
	Global          GlobalConfiguration
	Database        *DatabaseConfiguration
	DBBackend       PKIDBBackend
	Logging         []LogConfiguration
	OCSP            OCSPConfiguration
	VaultToken      string
}

// GlobalConfiguration - Global configration (section global from ini file)
type GlobalConfiguration struct {
	CaPublicKey          string `ini:"ca_public_key"`
	CaCertificate        string `ini:"ca_certificate"`
	CaPrivateKey         string `ini:"ca_private_key"`
	caPublicKey          []byte
	caCertificate        []byte
	caPrivateKey         []byte
	CaPassphrase         string `ini:"ca_passphrase"`
	Digest               string `ini:"digest"`
	SerialNumber         string `ini:"serial_number"`
	ValidityPeriod       int64  `ini:"validity_period"`
	AutoRenewStartPeriod int64  `ini:"auto_renew_start_period"`
	CrlPublicKey         string `ini:"crl_public_key"`
	CrlCertificate       string `ini:"crl_certificate"`
	CrlPrivateKey        string `ini:"crl_private_key"`
	crlPublicKey         []byte
	crlCertificate       []byte
	crlPrivateKey        []byte
	CrlPassphrase        string `ini:"crl_passphrase"`
	CrlValidityPeriod    int    `ini:"crl_validity_period"`
	CrlDigest            string `ini:"crl_digest"`
	ListAsHex            bool   `ini:"list_as_hex"`
	Backend              string `ini:"backend"`
	Sites                string `ini:"sites"`
	DefaultSite          string `ini:"default_site"`
	VaultInsecureSSL     bool   `ini:"vault_insecure_ssl"`
	VaultTimeout         int    `ini:"vault_timeout"`
	OcspPublicKey        string `ini:"ocsp_public_key"`
	OcspCertificate      string `ini:"ocsp_certificate"`
	OcspPrivateKey       string `ini:"ocsp_private_key"`
	OcspURI              string `ini:"ocsp_uri"`
	ocspPublicKey        []byte
	ocspCertificate      []byte
	ocspPrivateKey       []byte
	OcspPassphrase       string `ini:"crl_passphrase"`
	OcspDigest           string `ini:"ocsp_digest"`
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

// LogConfiguration - Log configuration
type LogConfiguration struct {
	Level       string
	LogLevel    int
	Destination string
	Option      string
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
	Type  string
	Value string
}

// X509KeyUsageData - X509 key usage
type X509KeyUsageData struct {
	Critical bool
	Type     string
}

// SigningRequest - Information about CSR to be signed
type SigningRequest struct {
	CSRData          *x509.CertificateRequest
	Extension        []X509ExtensionData
	ExtendedKeyUsage []X509ExtendedKeyUsageData
	SAN              []X509SubjectAlternateNameData
	BasicConstraint  []X509BasicConstraintData
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
	SerialNumber         *big.Int
	AutoRenewStartPeriod int64
	ValidityPeriod       int64
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
	AutoRenewValidityPeriod *int64   `json:"auto_renew_validity_period"`
	Certificate             string   `json:"certificate"`
	EndDate                 *int64   `json:"end_date"`
	AutoRenewStartPeriod    *int64   `json:"auto_renew_start_period"`
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

// TemplateConfig - template parsing
type TemplateConfig struct {
	Global           GlobalConfiguration
	Extension        []X509ExtensionData
	KeyUsage         []X509KeyUsageData
	ExtendedKeyUsage []X509ExtendedKeyUsageData
}

// TemplateKeyUsage - keyusage from template
type TemplateKeyUsage struct {
	Data string `ini:"data"`
}

// TemplateExtendedKeyUsage - extended keyusage from template
type TemplateExtendedKeyUsage struct {
	Data string `ini:"data"`
}

// TemplateExtension - Extension configuration in templates
type TemplateExtension struct {
	Critical   bool   `ini:"critical"`
	Data       string `ini:"data"`
	DataBase64 string `ini:"data:base64"`
}

// HTTPResult - Result of HTTP operation
type HTTPResult struct {
	Status     string
	StatusCode int
	Header     http.Header
	Content    []byte
}

// VaultKVResult - Result from Vault GET request
type VaultKVResult struct {
	RequestID string    `json:"request_id"`
	Data      VaultData `json:"data"`
}

// VaultData - payload from kv store
type VaultData struct {
	CaPublicKey        string `json:"ca_public_key"`
	CaPrivateKey       string `json:"ca_private_key"`
	CaPassphrase       string `json:"ca_passphrase"`
	CrlPublicKey       string `json:"crl_public_key"`
	CrlPrivateKey      string `json:"crl_private_key"`
	CrlPassphrase      string `json:"crl_passphrase"`
	DatabasePassphrase string `json:"database_passphrase"`
	// XXX: In theory this could be read from Vault too but github.com/lib/pq requires certificate _files_ for SSL client authentication.
	//      Creating temporary files for github.com/lib/pq would create a security risk by exposing the unencrypted private SSL key (but could be
	//       mitigated by enforcing appropriate file permissions).
	//	DatabaseSSLCert    string `json:"database_sslcert"`
	//	DatabaseSSLKey     string `json:"database_sslkey"`
	//	DatabaseSSLCa      string `json:"database_sslca"`
	OcspPublicKey  string `json:"ocsp_public_key"`
	OcspPrivateKey string `json:"ocsp_private_key"`
	OcspPassphrase string `json:"ocsp_passphrase"`
}

// OCSPConfiguration - OCSP configuration
type OCSPConfiguration struct {
	Address string
	Path    string
}
