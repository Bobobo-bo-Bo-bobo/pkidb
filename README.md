[TOC]
----
## Formats
### Serial number formats

Serial numbers can be given as the decimal or hexadecimal representation. If the hexadecimal representation is used, it must be prefixed by `0x`, e.g. `0xdeadc0de` instead of `3735929054`

### Time formats
Every option requiring a time use the same time format. It is a ASN1 GERNERALIZEDTIME string in the format `YYYYMMDDhhmmssZ`

## General options
General options can always be used and are not bound to a specific command. 

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `--version` | - | - | Shows version |
| `--config` | Path to configuration file | `/etc/pkidb/config.ini` | Use an alternate configuration file |
| `--help` | -  | - | Show the help |

## Usage and commands
### Add dummy certificate in the backend - `add-dummy`
The `add-dummy` command adds a dummy certificate, identified by the serial number, in the backend database.

If the serial number is not given on the command line it will be read from standard input.

This can be used if the certificate has been issued but the certificate file is not present (usually happens while migrating or importing a existing PKI) but the serial number (and optionally the start date, end date or subject) is known.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `--subject` | Certificate subject | - | Sets the certificate subject for the dummy entry |
| `--start` | The start time of the certificate (notBefore) | - | Start of the certificate |
| `--end` | The expiry time of the certificate (notAfter) | - | Expiry time of the certificate |

### Backup/dump of the database - `backup`
The `backup` command dumps the content of the backend database in JSON format. This can be used to backup the PKI database and is the only supported way to migrate between different database backends. If no output file is given the dump will be written to standard output.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–output` | Output file | - | Write database dump to a file instead of standard out |

### Delete a certifcate from the backend - `delete`
The `delete` command removes a certficiate identified by the serial number from the backend database. If the serial number is not given on the command line it will be read from standard input.

***<u>Note:</u>*** *This options should only be used in special circumstances. Usually (for instance if a certificate has been issued with wrong information like missing or misspelled `subjectAltName`) it should be revoked and reissued instead.*

### Export the public key of a certificate - `export`
The `export` command writes the base64 encoded X509 data of a certificate (PEM format). The serial number of the certificate must be given or will be read from the standard input. The certificate will be written to standard output or to a file if the `--output` option is used. 

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–output` | Output file | - | Write database dump to a file instead of standard out |

### Generate the certificate revocation list - `gencrl`
The `gencrl` command generates the certificate revocation list containing information about revoked certificates. The certificate revocation list will be written to standard output or to a file if `--output` is used.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–output` | Output file | - | Write database dump to a file instead of standard out |

This command requires the public and private keys of the certificate to (configured as `crl_public_key` and `crl_private_key` in the configuration file) sign the revocation list. Obviously this certificate requires the correct certificate flags (CRL Sign) and extensions (OCSP Signing). The certificate revocation list is only valid for a certain amount of time (defined as `crl_validity_period` in the configuration file) and must be renewed regularily.

The generation function to generate the certificate revocation list ([x509.Certificate.CreateCRL](https://golang.org/pkg/crypto/x509/#Certificate.CreateCRL)) always use SHA256. This is hardcoded in the function and can't be changed.

### Verify integrity of the backend data - `healthcheck`
***Note:*** At the moment this command will do nothing, because of a known bug in Go! - [encoding/asn1: valid GeneralizedTime not parsed #15842](https://github.com/golang/go/issues/15842) - hopefully fixed in Go 1.14. Futhermore this command is considered as deprecated, because discrepancies can only occur if the database was modified directly (obviously a unsupported case) and will be removed in future versions.

<strike>
To verify the integrity the `healthcheck` command is used. It will compare the information stored in the certificates public key with the fields of the database backend and report discrepancies. The -f option can be used to replace the database fields with the data extracted from the certificate.
</strike>

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `--fix` | - | - | Stored data will be replaced with data from the certifiate stored in the database. |

### General "housekeeping" - `housekeeping`
The `housekeeping` command should be run at regular intervals. It will check all certificates in the database for expiration and renew auto renewable certificates (if the option `--auto-renew` is used).

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–auto-renew` | - | - | Renew auto renewable certificates that will expire |
| `-–period` | New validity period in days | Value stored in the backend database | New validity period for auto renewed certificate in days |

***Note:*** Auto renewal will fail if the certificate uses `GENERALIZEDTIME` to encode dates instead of `UTCTIME` due to a known bug in Go! - [encoding/asn1: valid GeneralizedTime not parsed #15842](https://github.com/golang/go/issues/15842).

### Import a certificate - `import`
To import a certificate the import command is used. If a file name is given it will be read from the file, otherwise it will be read from standard input.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–auto-renew` | - | - | Mark certificate as auto renewable |
| `-–csr` | Certificate signing request in PEM format | - | Certificate signing request used for certificate creation |
| `-–delta` | Days before expiration to start auto renew process | - | For auto renewable certificates the auto renew process starts if the time til expiration is less than the given number of days |
| `-–period` | New validity period in days for auto renewed certificate | Value of validity_period in the configuration file | New validity period for auto renewed certificate |
| `-–revoked` | `reason,time` | - | Import certificate and mark it as revoked. `reason` is the revocation reason and can be one of |
| | | | `unspecified`, `keyCompromise`, `CACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`, `removeFromCRL`, `aACompromise` (see [RFC 5280, Section 5.3.1. Reason Code](https://tools.ietf.org/html/rfc5280#section-5.3.1). |
| | | |`time` is the time of the revocation |

### List certificates - `list`
Using the `list` command a list of serial numbers of certificates from the backend. The list will be written to standard output if the option `--output` is not used.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–expired` | - | - | List serial numbers of expired certificates |
| `-–invalid` | - | - | List serial numbers of invalid certificates. Certficates are considered invalid if their start date (notBefore) is in the future |
| `-–output` | Output file | - | Write serial numbers of listed certificate to a file instead to standard output |
| `-–revoked` | - | - | List serial numbers of revoked certificates |
| `-–temporary` | - | - | List "certificates" marked as temporary. Temporary certficates are dummy settings used to "lock" serial numbers during signing of a certificate signing request |
| `-–valid` | - | - | List serial numbers of valid certificates. A certificates is considered valid if it is not temporary, not revoked and the validity period (notBefore .. notAfter) has started and the certificate is not expired |

Serial numbers are always printed as decimal or hexadecimal, as configured by `list_as_hex` in the configuration file and/or the environment variable `PKIDB_GLOBAL_LIST_AS_HEX`.

### Renew certificates - `renew`
The `renew` command renews a cerificate. The serial number of the certificate must be given on the command line or it will be read from the standard input. The new certificate will be written to standard output or to a file by using the `--output` option.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–output` | Output file | - | Write serial numbers of listed certificate to a file instead to standard output |
| `-–period` | New validity period in days | `validity_period` from configuration file |

***Note:*** Because of a known bug in the Go! implementation - [encoding/asn1: valid GeneralizedTime not parsed #15842](https://github.com/golang/go/issues/15842) - renewal of certificates using `GENERALIZEDTIME` to encode dates instead of `UTCTIME` will fail.

### Restore database - `restore`
To restore the database from a JSON file (generated with the `backup` command) the `restore` command can be used. If the filename of the input data is given on the command line the content will be read from the file, otherwise standard input is used. `backup` and `restore` can be used to migrate to another database type.

### Revoking a certificate - `revoke`
By using the `revoke` command a certificate, identified by its serial number, can be revoked. The serial number must be given on the command line or it will be read from standard input. If not specified the revocation reason will be set to `unspecified`.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–force` | - | - | Revoke certificate even it is not present in the database. A dummy entry will be inserted in the database and marked as revoked |
| `-–reason` | revocation reason | `unspecified` | Set revocation reason for certificate. |
| | | | The revocation reason is specified in [RFC 5280, Section 5.3.1 Reason Code](https://tools.ietf.org/html/rfc5280#section-5.3.1) and can be one of |
| | | | `unspecified`, `keyCompromise`, `CACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`, `removeFromCRL`, `aACompromise` |
| `-–revocation-date` | revocation date for certificate | current date and time | Revocation date must be an ASN1 GERNERALIZEDTIME string in the format `YYYYMMDDhhmmssZ`. If not given, the current date will be used |

### Search a certificate - `search`
The `search` command searches certificate subject for a given string. Search string can be given on the command line or will be read from standard input if omitted. SQL wildcards like `%` can be used. The serial numbers matching the search will be printed to standard output or to the file given by the `--output` option.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–output` | Output file | - | Write database dump to a file instead of standard output |

### Modify meta data - `set`
The `set` command is used to modify meta data of a certificate identified by the serial number. The serial number of the certificate must be given on the command line or will be read from the standard input if omitted.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–auto-renew` | - | - | Mark a certificate as auto renewable |
| `-–auto-renew-start-period` | - | - |Set auto renew start period in days. If there are less than period days left until certificate expiration it will be renewed. The housekeeping command will renew the certificate |
| `-–auto-renew-validity-period` | - | - | Renew the certificate for period days. If not specified the setting from the configuration file will be used |
| `-–no-auto-renew` | - | - | Remove auto renewable flag from certificates meta data |
| `-–csr` | - | - | Set certificate signing request |

### Show certificate data - `show`
`show` shows information of a certificate identified by the serial number. The serial number of the certificate must be given on the command line or will be read from standard input. The certificate information will be written to standard output or to a file if the `--output` option is used.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–output` | Output file | - | Write database dump to a file instead of standard out |

### Signing a certificate signing request - `sign`
The `sign` command is used to sign a certificate signing request. If the file name containing the certificate signing request is provided it will be read, otherwise the signing request will be read from standard input. The signed public key will be written to standard output or to a file if `--output` option is used.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–extension` | `extdata` | - | X509 extension to be included in new certificate. Can be repeated for multiple extensions. extdata is a comma separated list of |
|  |  |  | `name` - Name of the X509 extension |
|  |  |  | `critical` - Critical flag. 0: False, 1: True |
|  |  |  | `subject` - Subject (usually empty) |
|  |  |  | `issuer` - Issuer (usually empty) |
|  |  |  | `data` - data of the extension |
| `-–extended-keyusage` | `flags` | - | Comma separated list of extended key usage bits. Additionally dotted numeric OID are allowed too, e.g. `1.2.3.4.5`. |
|  |  |  | Known extended key usage bits are defined in RFC 5280 as `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `msCodeInd`, `msCodeCom`, `msCTLSign`, `msSGC`,`nsSGC`, `any` |
| `-–san` | `alternatename` | - | `subjectAltName` extension |
| `-–auto-renew` | - | - | Mark certificate as auto renewable. The `housekeeping` command (with the `--auto-renew` option) will take care of this |
| `-–basic-constraint` | `data` | - | Set basic constraints for the new certificate |
| `-–keyusage` | `flags` | - | Comma separated list of keyUsage bits. |
|  |  |  | Known `keyUsage` bits according RFC 5280 to are: `digitalSignature`, `nonRepudiation` (or `contentCommitment`), `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly` |
| `-–output` | Output file | - | Write serial numbers of listed certificate to a file instead to standard output |
| `-–start-in` | `startin` | current date and time | Validity of the new certificate starts in startin days |
| `-–template` | `templatefile` | - | Use a template file for certificate signing |
| `-–valid-for` | `validfor` | `validity_period` in the configuration or the template file | New certificate will be valid for validfor days |

#### Basic constraints
[RFC 5280 - Section 4.2.1.9](https://tools.ietf.org/html/rfc5280#section-4.2.1.9) only defines two basic constraints - `CA` and `pathlen` - and doesn't define the criticality of the basic constraints. As a consequence the critical flag has been removed for basic constraints and basic constraints are limited to `CA` and `pathlen`.

Additionally supplied `pathlen` will not be set (and an error occures) if `CA` is not set and key usage does not include `keyCertSign`.
This is mandated by RFC 5280: _<u>CAs MUST NOT include the pathLenConstraint field unless the CA boolean is asserted and the key usage extension asserts the keyCertSign bit</u>._)

#### Subject alternative names
The criticality of the subject alternative names depend on the subject fields (see [RFC 5280 - Section 4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)). To ensure generation of valid (according to RFC 5280) certificates the possibility to define the criticality has been removed.

#### Key usage flags are always marked as critical
Keyusage flags (`pkidb sign --keyusage=...`) are **_always_** defined as CRITICAL as defined in [RFC 5280 - Section 4.2.1.3](https://tools.ietf.org/html/rfc5280#section-4.2.1.3) (_<u>When present, conforming CAs SHOULD mark this extension as critical</u>_).

Hence the option to set the criticality flag of the keyusage flags has been removed.

#### Extended key usage flags
[RFC 5280 - Section 4.2.1.12](https://tools.ietf.org/html/rfc5280#section-4.2.1.12) defines the behavior for clients to process key usage and extended key usage flags independently and use the certificate as defined by *BOTH* flags. So it's pointless to define the critical flag and the possibility to define it has been removed.

### Statistics - `statistics`
The `statistics` command will print a small summary of stored certificates to standard output.
***Note:*** Only the keysizes and hashing algorithm of valid certificates are shown.

----

# Changes from `python-pkidb`
## Getopt short options are no longer supported
Due to the switch to Go! the command-line parsing changes to standard Go! behavior and as a consequence getopt short options are no longer supported.

## Date format
If dates are specified the format must **always** be a ASN1 GERNERALIZEDTIME string in the format `YYYYMMDDhhmmssZ`

## Basic constraints
[RFC 5280 - Section 4.2.1.9](https://tools.ietf.org/html/rfc5280#section-4.2.1.9) only defines two basic constraints - `CA` and `pathlen` - and doesn't define the criticality of the basic constraints. As a consequence the critical flag has been removed for basic constraints and basic constraints are limited to `CA` and `pathlen`.

Additionally supplied `pathlen` will not be set (and an error occures) if `CA` is not set and key usage does not include `keyCertSign`.
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
The generation function to generate the certificate revocation list ([x509.Certificate.CreateCRL](https://golang.org/pkg/crypto/x509/#Certificate.CreateCRL)) always use SHA256. This is hardcoded in the function and can't be changed, so the value for `crl_digest` will be ignored.

## Renewing a certificate will no longer change the `notBefore` date
Renewal of certificate using `pkidb renew` will no longer change the start date (`notBefore`) of the certificate, only the end date (`notAfter`) will be changed.

## Output format for serial numbers
Serial numbers are always printed as decimal or hexadecimal, as configured by `list_as_hex` in the configuration file and/or the environment variable `PKIDB_GLOBAL_LIST_AS_HEX`.

## Writing result of the `search` command to a file
The `search` command allows for writing of the result to a file (instead if standard output) by adding the `--output` option.

----

# Migration from `python-pkidb`
## Encrypted private keys
Due to the inability of Golang to handle encryptes private SSL keys in PEM format (see [crypto/tls: needs a convenience function for reading encrypted keys](https://github.com/golang/go/issues/6722))
all encrypted private keys (for the CA and/or CRL signing) must be converted the PKCS8 format, encrypted with PKCS5 v2 algorithm and stored in the DER format.
This can be done by using `openssl pksc8` e.g.:

`openssl pkcs8 -topk8 -in ca_private.key -out ca_private.der -outform DER`

:heavy_exclamation_mark: <u>**Be very careful when using copy&paste to pass in the password, because `openssl` may use the linebreak in the password of the PKCS8 file**</u> :heavy_exclamation_mark:

## Value of `version` in the database
Contrary to the Python implementation, Go starts the SSL version at 1 instead of 0. The database backend stores the version as it was used by Python. To update the version values in the database by running:

`UPDATE certificate SET version=3 WHERE version=2;`

----
## Known issues
### Go!
#### `asn1: time did not serialize back to the original value and may be invalid`
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

Luckily the impact is limited only to the renewal of such a certificate (e.g. `pkidb renew ...`).

