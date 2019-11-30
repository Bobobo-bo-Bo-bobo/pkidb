package main

// PKIConfiguration - Configuration
type PKIConfiguration struct {
	CAPublicKey  []byte
	CAPrivateKEy []byte
	Global       GlobalConfiguration
	Database     *DatabaseConfiguration
}

// GlobalConfiguration - Global configration (section global from ini file)
type GlobalConfiguration struct {
	CaPublicKey          string `ini:"ca_public_key"`
	CaPrivateKey         string `ini:"ca_private_key"`
	CaPassphrase         string `ini:"ca_passphrase"`
	Digest               string `ini:"digest"`
	SerialNumber         string `ini:"serial_number"`
	ValidityPeriod       string `ini:"validity_period"`
	AutoRenewStartPeriod string `ini:"auto_renew_start_period"`
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
