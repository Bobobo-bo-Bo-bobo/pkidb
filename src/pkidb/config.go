package main

import (
	"crypto/x509"
	"time"
)

// PKIConfiguration - Configuration
type PKIConfiguration struct {
	CAPublicKey   []byte
	CAPrivateKey  []byte
	Global        GlobalConfiguration
	Database      *DatabaseConfiguration
	CACertificate *x509.Certificate
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
	Subject  string
	Issuer   string
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
