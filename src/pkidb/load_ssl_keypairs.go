package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
)

// LoadSSLKeyPairs - load CA/CRL SSL keys and decrypt private key
func LoadSSLKeyPairs(cfg *PKIConfiguration) error {
	// XXX: future versions could use other storage like HashiCorp Vault. This should check the url scheme.

	// Note: In special setups a configuration without CA keys can occur. For instance if it is a host
	//		 only generating the CRL.
	if cfg.Global.CaPublicKey != "" && cfg.Global.CaPrivateKey != "" {
		pub, priv, err := ReadEncryptedKeyPair(cfg.Global.CaPublicKey, cfg.Global.CaPrivateKey, cfg.Global.CaPassphrase)
		cacert, err := tls.X509KeyPair(pub, priv)
		if err != nil {
			return err
		}
		cfg.CACertificate = &cacert
		caPub, _ := pem.Decode(pub)
		cfg.CAPublicKey, err = x509.ParseCertificate(caPub.Bytes)
		if err != nil {
			return err
		}
	} else {
		cfg.CAPublicKey = nil
		cfg.CACertificate = nil
	}

	if cfg.Global.CrlPublicKey != "" && cfg.Global.CrlPrivateKey != "" {
		pub, priv, err := ReadEncryptedKeyPair(cfg.Global.CrlPublicKey, cfg.Global.CrlPrivateKey, cfg.Global.CrlPassphrase)
		crlcert, err := tls.X509KeyPair(pub, priv)
		if err != nil {
			return err
		}
		cfg.CRLCertificate = &crlcert
		crlPub, _ := pem.Decode(pub)
		cfg.CRLPublicKey, err = x509.ParseCertificate(crlPub.Bytes)
		if err != nil {
			return err
		}
	} else {
		cfg.CRLPublicKey = nil
		cfg.CRLCertificate = nil
	}

	return nil
}
