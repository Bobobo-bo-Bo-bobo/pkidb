package main

import (
	"crypto/x509"
)

const name string = "pkidb"
const version string = "1.0.0-2019.11.30"

// DigestMap - Map OpenSSL digest to Golang x509.SignatureAlgorithm
var DigestMap = map[string]x509.SignatureAlgorithm{
	"md5":    x509.MD5WithRSA,
	"sha1":   x509.SHA1WithRSA,
	"sha256": x509.SHA256WithRSA,
	"sha384": x509.SHA384WithRSA,
	"sha512": x509.SHA512WithRSA,
}
