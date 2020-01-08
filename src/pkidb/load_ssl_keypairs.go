package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// LoadSSLKeyPairs - load CA/CRL SSL keys and decrypt private key
func LoadSSLKeyPairs(cfg *PKIConfiguration) error {
	// Note: In special setups a configuration without CA keys can occur. For instance if it is a host
	//               only generating the CRL.
	if cfg.Global.CaPublicKey != "" && cfg.Global.CaPrivateKey != "" {
		pub, priv, err := DecryptEncryptedKeyPair(cfg.Global.caPublicKey, cfg.Global.caPrivateKey, cfg.Global.CaPassphrase)
		cacert, err := tls.X509KeyPair(pub, priv)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		cfg.CACertificate = &cacert
		caPub, _ := pem.Decode(pub)
		cfg.CAPublicKey, err = x509.ParseCertificate(caPub.Bytes)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	} else {
		cfg.CAPublicKey = nil
		cfg.CACertificate = nil
	}

	if cfg.Global.CrlPublicKey != "" && cfg.Global.CrlPrivateKey != "" {
		pub, priv, err := DecryptEncryptedKeyPair(cfg.Global.crlPublicKey, cfg.Global.crlPrivateKey, cfg.Global.CrlPassphrase)
		crlcert, err := tls.X509KeyPair(pub, priv)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		cfg.CRLCertificate = &crlcert
		crlPub, _ := pem.Decode(pub)
		cfg.CRLPublicKey, err = x509.ParseCertificate(crlPub.Bytes)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	} else {
		cfg.CRLPublicKey = nil
		cfg.CRLCertificate = nil
	}

	return nil
}
