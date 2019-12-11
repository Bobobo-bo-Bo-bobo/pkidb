----
# Changes from `python-pkidb`
## Getopt short options are no longer supported
Due to the switch Go! the command-line parsing changes to standard Go! behavior and as a consequence getopt short options are no longer supported.

## Basic constraints
[RFC 5280 - Section 4.2.1.9](https://tools.ietf.org/html/rfc5280#section-4.2.1.9) only defines two basic constraints - `CA` and `pathlen` - and doesn't define the criticality of the basic constraints. As a consequence the critical flag has been removed for basic constraints and basic constraints are limited to `CA` and `pathlen`.

Additionally supplied `pathlen` will not set (and an error occures) if `CA` is not set and key usage does not include `keyCertSign`.
This is mandated by RFC 5280: _<u>CAs MUST NOT include the pathLenConstraint field unless the CA boolean is asserted and the key usage extension asserts the keyCertSign bit</u>._)

## Subject alternative names
The criticality of the subject alternative names depend on the subject fields (see [RFC 5280 - Section 4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)). To ensure generation of valid (according to RFC 5280) certificates the possibility to define the criticality has been removed.

## Key usage flags are always marked as critical
Keyusage flags (`pkidb sign --keyusage=...`) are **_always_** defined as CRITICAL as defined in [RFC 5280 - Section 4.2.1.3](https://tools.ietf.org/html/rfc5280#section-4.2.1.3) (_<u>When present, conforming CAs SHOULD mark this extension as critical</u>_).

Hence the option to set the criticality flag of the keyusage flags has been removed.

## Extended key usage flags
[RFC 5280 - Section 4.2.1.12](https://tools.ietf.org/html/rfc5280#section-4.2.1.12) defines the behavior for clients to process key usage and extended key usage flags independently and use the certificate as defined by *BOTH* flags. So it's pointless to define the critical flag and the possibility to define it has been removed.

The extended key usage flag `any` has been added.

## Signing algorithm for certificate revocation list is ignored
The generation function for certificate revocation list ([x509.Certitifate.CreateCRL](https://golang.org/pkg/crypto/x509/#Certificate.CreateCRL)) always use SHA256. This is hardcoded in the function and can't be changed, so the value for `crl_digest` will be ignored.

## Renewing a certificate will no longer change the `notBefore` date
Renewal of certificate using `pkidb renew` will no longer change the start date (`notBefore`) of the certificate, only the end date (`notAfter`) will be changed.

# Migration from `python-pkidb`
## Encrypted private keys
Due to the inability of Golang to handle encryptes private SSL keys (see [crypto/tls: needs a convenience function for reading encrypted keys](https://github.com/golang/go/issues/6722))
all encrypted private keys (for the CA and/or CRL signing) must be converted the PKCS8 format, encrypted with PKCS5 v2 algorithm and stored in the DER format.
This can be done by using `openssl pksc8` e.g.:

`openssl pkcs8 -topk8 -in ca_private.key -out ca_private.der -outform DER`

## Value of `version` in the database
Contrary to the Python implementation, Go starts the SSL version at 1 instead of 0. The database backend stores the version as it was used by Python. To update the version values run:

`UPDATE certificate SET version=3 WHERE version=2;`

----
## Known issues
### Go!
#### `encoding/asn1: valid GeneralizedTime not parsed`
This bug is triggered if a certificate uses `GENERALIZEDTIME` to encode dates instead of `UTCTIME`. This can be checked with `openssl asn1parse`, e.g.:

```
[user@host:~]$ openssl asn1parse -i -in b0rken.pem
    0:d=0  hl=4 l=1471 cons: SEQUENCE
    4:d=1  hl=4 l= 935 cons:  SEQUENCE
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=   8 prim:   INTEGER           :7A7270A09101D38B
   23:d=2  hl=2 l=  13 cons:   SEQUENCE
   25:d=3  hl=2 l=   9 prim:    OBJECT            :sha512WithRSAEncryption
   36:d=3  hl=2 l=   0 prim:    NULL
[...]
  109:d=2  hl=2 l=  42 cons:   SEQUENCE
  111:d=3  hl=2 l=  19 prim:    GENERALIZEDTIME   :20160106171308+0000
  132:d=3  hl=2 l=  19 prim:    GENERALIZEDTIME   :20190105171308+0000
  153:d=2  hl=3 l= 141 cons:   SEQUENCE
[...]
  943:d=1  hl=2 l=  13 cons:  SEQUENCE
  945:d=2  hl=2 l=   9 prim:   OBJECT            :sha512WithRSAEncryption
  956:d=2  hl=2 l=   0 prim:   NULL
  958:d=1  hl=4 l= 513 prim:  BIT STRING
```

instead of:

```
[user@host:~]$ openssl asn1parse -i -in utctime.pem
    0:d=0  hl=4 l=1057 cons: SEQUENCE
    4:d=1  hl=4 l= 521 cons:  SEQUENCE
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=   8 prim:   INTEGER           :76BBE54F84C600BB
   23:d=2  hl=2 l=  13 cons:   SEQUENCE
   25:d=3  hl=2 l=   9 prim:    OBJECT            :sha512WithRSAEncryption
   36:d=3  hl=2 l=   0 prim:    NULL
[...]
  109:d=2  hl=2 l=  30 cons:   SEQUENCE
  111:d=3  hl=2 l=  13 prim:    UTCTIME           :180701110127Z
  126:d=3  hl=2 l=  13 prim:    UTCTIME           :210630110127Z
  141:d=2  hl=2 l=  92 cons:   SEQUENCE
[...]
  529:d=1  hl=2 l=  13 cons:  SEQUENCE
  531:d=2  hl=2 l=   9 prim:   OBJECT            :sha512WithRSAEncryption
  542:d=2  hl=2 l=   0 prim:   NULL
  544:d=1  hl=4 l= 513 prim:  BIT STRING

```

This is a known bug - [encoding/asn1: valid GeneralizedTime not parsed #15842](https://github.com/golang/go/issues/15842) - hopefully fixed in Go 1.14.

#### `crypto/x509: CRL generated by Certificate.CreateCRL is non-conforming`
The certificate revocation list generated by Go! uses the wrong version
* [crypto/x509: CRL generated by Certificate.CreateCRL is non-conforming and should be version 2](https://github.com/golang/go/issues/35428)

