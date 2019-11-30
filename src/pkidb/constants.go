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

/*
  Note: RFC 3280 - 4.1.2.2  Serial number (see https://www.ietf.org/rfc/rfc3280.txt) states:

4.1.2.2  Serial number

   The serial number MUST be a positive integer assigned by the CA to
   each certificate.  It MUST be unique for each certificate issued by a
   given CA (i.e., the issuer name and serial number identify a unique
   certificate).  CAs MUST force the serialNumber to be a non-negative
   integer.

   Given the uniqueness requirements above, serial numbers can be
   expected to contain long integers.  Certificate users MUST be able to
   handle serialNumber values up to 20 octets.  Conformant CAs MUST NOT
   use serialNumber values longer than 20 octets.

   Note: Non-conforming CAs may issue certificates with serial numbers
   that are negative, or zero.  Certificate users SHOULD be prepared to
   gracefully handle such certificates.


 -> so 0x7fffffffffffffff is the maximum serial number because of "Certificate users MUST be able to
    handle serialNumber values up to 20 octets"

*/
const MaximumSerialNumberString = "0x7fffffffffffffff"
