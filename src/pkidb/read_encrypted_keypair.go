package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/youmark/pkcs8"
	"io/ioutil"
)

// ReadEncryptedKeyPair - Read public/private key pair from files
// Parameter:
//  pub string  - file containing public key
//  priv string - file containing encrypted private key; this file MUST be in PKCS8 in DER form encrypted with PKCS5 v2 algorithm
//  pass string - password for encrypted private key
//
// Return:
//  []byte - public SSL key in PEM format
//  []byte - private (decrypted) SSL key in PEM format
//  error  - error
func ReadEncryptedKeyPair(pub string, priv string, pass string) ([]byte, []byte, error) {
	var privateKeyString = "-----BEGIN PRIVATE KEY-----\n"

	publicKey, err := ioutil.ReadFile(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	binaryEncryptedPrivateKey, err := ioutil.ReadFile(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// parse encrypted PKCS8 DER data
	binaryDecryptedPrivateKey, err := pkcs8.ParsePKCS8PrivateKey(binaryEncryptedPrivateKey, []byte(pass))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	binaryDecryptedPrivateKeyMarshalled, err := x509.MarshalPKCS8PrivateKey(binaryDecryptedPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	base64DecryptedPrivateKey := base64.StdEncoding.EncodeToString(binaryDecryptedPrivateKeyMarshalled)

	// tls.X509KeyPair requires PEM block in "-----BEGIN ...-----", each base64 encoded line consist of 64 chars each
	lines64Chars := len(base64DecryptedPrivateKey) / 64
	for i := 0; i < lines64Chars; i++ {
		privateKeyString += base64DecryptedPrivateKey[64*i:64*(i+1)] + "\n"
	}
	if len(base64DecryptedPrivateKey)%64 != 0 {
		privateKeyString += base64DecryptedPrivateKey[64*lines64Chars:len(base64DecryptedPrivateKey)] + "\n"
	}
	privateKeyString += "-----END PRIVATE KEY-----"

	return publicKey, []byte(privateKeyString), nil
}
