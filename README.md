**_Note:_** Because I'm running my own servers for several years, main development is done at at https://git.ypbind.de/cgit/pkidb/

----

## Formats
### Serial number formats

Serial numbers can be given as the decimal or hexadecimal representation. If the hexadecimal representation is used, it must be prefixed by `0x`, e.g. `0xdeadc0de` instead of `3735929054`

### Time formats
Every option requiring a time use the same time format. It is a ASN1 GERNERALIZEDTIME string in the format `YYYYMMDDhhmmssZ`

### Multi-site
The global configuration file can contain a list of "sites" pointing to other configuration files. By selecting a site (global option `--site`) the content of the corresponding
configuration file is read and merged with the values read from the global configuration file.

## General options
General options can always be used and are not bound to a specific command. 

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `--config` | Path to configuration file | `/etc/pkidb/config.ini` | Use an alternate configuration file |
| `--help` | -  | - | Show the help |
| `--site` | - | - |  Additional site configuration to load |
| `--version` | - | - | Shows version |

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

### Delete a certificate from the backend - `delete`
The `delete` command removes a certificate identified by the serial number from the backend database. If the serial number is not given on the command line it will be read from standard input.

***<u>Note:</u>*** *This options should only be used in special circumstances. Usually it should be revoked and reissued instead, e.g.  if a certificate has been issued with wrong information like missing or misspelled `subjectAltName`*

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

This command requires the public and private keys of the certificate to (configured as `crl_public_key` and `crl_private_key` in the configuration file) sign the revocation list. Obviously this certificate requires the correct certificate flags (CRL Sign) and extensions (OCSP Signing). The certificate revocation list is only valid for a certain amount of time (defined as `crl_validity_period` in the configuration file) and must be renewed regularly.

The generation function to generate the certificate revocation list ([x509.Certificate.CreateCRL](https://golang.org/pkg/crypto/x509/#Certificate.CreateCRL)) always use SHA256. This is hardcoded in the function and can't be changed.

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
| `-–period` | New validity period in days for auto renewed certificate | Value of `validity_period` in the configuration file | New validity period for auto renewed certificate |
| `-–revoked` | `reason,time` | - | Import certificate and mark it as revoked. `reason` is the revocation reason and can be one of |
| | | | `unspecified`, `keyCompromise`, `CACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`, `removeFromCRL`, `aACompromise` (see [RFC 5280, Section 5.3.1. Reason Code](https://tools.ietf.org/html/rfc5280#section-5.3.1) |
| | | |`time` is the time of the revocation |

### List certificates - `list`
Using the `list` command a list of serial numbers of certificates from the backend. The list will be written to standard output if the option `--output` is not used.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `-–expired` | - | - | List serial numbers of expired certificates |
| `-–invalid` | - | - | List serial numbers of invalid certificates. Certificates are considered invalid if their start date (notBefore) is in the future |
| `-–output` | Output file | - | Write serial numbers of listed certificate to a file instead to standard output |
| `-–revoked` | - | - | List serial numbers of revoked certificates |
| `-–temporary` | - | - | List "certificates" marked as temporary. Temporary certificates are dummy settings used to "lock" serial numbers during signing of a certificate signing request |
| `-–valid` | - | - | List serial numbers of valid certificates. A certificates is considered valid if it is not temporary, not revoked and the validity period (notBefore .. notAfter) has started and the certificate is not expired |

Serial numbers are always printed as decimal or hexadecimal, as configured by `list_as_hex` in the configuration file and/or the environment variable `PKIDB_GLOBAL_LIST_AS_HEX`.

### OCSP responder service - `ocsp`
The `ocsp` command starts `pkidb` as a HTTP server to accept and respond to OCSP requests. The service does **not** fork and will remain in the foreground (making it easy to integration as a systemd service). OCSP requests can be submitted by HTTP POST and HTTP GET as specified in [RFC 6960 - X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://www.ietf.org/rfc/rfc6960.txt).

For OCSP requests using the POST method the content type **MUST** be set to `application/ocsp-request`.
The content type of the reply is always `application/ocsp-response`.

| Option | Argument | Default | Description |
|:-------|:--------:|:--------|:-------------|
| `--uri` | OCSP URI | - | OCSP URI to listen for OCSP requests |

By providing the `--uri` option the value of `ocsp_uri` will be replaced by the parameter of the option.

### Renew certificates - `renew`
The `renew` command renews a certificate. The serial number of the certificate must be given on the command line or it will be read from the standard input. The new certificate will be written to standard output or to a file by using the `--output` option.

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
| `-–reason` | revocation reason | `unspecified` | Set revocation reason for certificate |
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
| `-–extension` | `extdata` | - | X509 extension to be included in new certificate. Can be repeated for multiple extensions. `extdata` is a comma separated list of |
|  |  |  | `name` - Name of the X509 extension |
|  |  |  | `critical` - Critical flag. 0: False, 1: True |
|  |  |  | `subject` - Subject (usually empty) |
|  |  |  | `issuer` - Issuer (usually empty) |
|  |  |  | `data` - data of the extension |
| `-–extended-keyusage` | `flags` | - | Comma separated list of extended key usage bits. Additionally dotted numeric OID are allowed too, e.g. `1.2.3.4.5` |
|  |  |  | Known extended key usage bits are defined in RFC 5280 as `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `msCodeInd`, `msCodeCom`, `msCTLSign`, `msSGC`,`nsSGC`, `any` |
| `-–san` | `alternatename` | - | `subjectAltName` extension |
| `-–auto-renew` | - | - | Mark certificate as auto renewable. The `housekeeping` command (with the `--auto-renew` option) will take care of this |
| `-–basic-constraint` | `data` | - | Set basic constraints for the new certificate |
| `-–keyusage` | `flags` | - | Comma separated list of `keyUsage` bits |
|  |  |  | Known `keyUsage` bits according RFC 5280 to are: `digitalSignature`, `nonRepudiation` (or `contentCommitment`), `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly` |
| `-–output` | Output file | - | Write serial numbers of listed certificate to a file instead to standard output |
| `-–start-in` | `startin` | current date and time | Validity of the new certificate starts in `startin` days |
| `-–template` | `templatefile` | - | Use a template file for certificate signing |
| `-–valid-for` | `validfor` | `validity_period` in the configuration or the template file | New certificate will be valid for `validfor` days |

#### Basic constraints
[RFC 5280 - Section 4.2.1.9](https://tools.ietf.org/html/rfc5280#section-4.2.1.9) only defines two basic constraints - `CA` and `pathlen` - and doesn't define the criticality of the basic constraints. As a consequence the critical flag has been removed for basic constraints and basic constraints are limited to `CA` and `pathlen`.

Additionally supplied `pathlen` will not be set (and an error occurs) if `CA` is not set and key usage does not include `keyCertSign`.
This is mandated by RFC 5280: _<u>CAs MUST NOT include the pathLenConstraint field unless the CA boolean is asserted and the key usage extension asserts the keyCertSign bit</u>._)

#### Subject alternative names
The criticality of the subject alternative names depend on the subject fields (see [RFC 5280 - Section 4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)). To ensure generation of valid (according to RFC 5280) certificates the possibility to define the criticality has been removed.

#### Key usage flags are always marked as critical
Key usage flags (`pkidb sign --keyusage=...`) are **_always_** defined as CRITICAL as defined in [RFC 5280 - Section 4.2.1.3](https://tools.ietf.org/html/rfc5280#section-4.2.1.3) (_<u>When present, conforming CAs SHOULD mark this extension as critical</u>_).

Hence the option to set the criticality flag of the key usage flags has been removed.

#### Extended key usage flags
[RFC 5280 - Section 4.2.1.12](https://tools.ietf.org/html/rfc5280#section-4.2.1.12) defines the behavior for clients to process key usage and extended key usage flags independently and use the certificate as defined by *BOTH* flags. So it's pointless to define the critical flag and the possibility to define it has been removed.

### Statistics - `statistics`
The `statistics` command will print a small summary of stored certificates to standard output.
***Note:*** Only the key sizes and hashing algorithm of valid certificates are shown.

---

## Configuration
The configuration file is structured like a INI file. It contains at least two sections. The global section and a backend specific section based on the backend selected in the global section.
As it will contain sensitive informations, if not stored in [Hashicorp Vault](https://www.vaultproject.io/), like the path and the password for the private key of your certificate authority, access to this configuration file should be restricted!

### Hashicorp Vault support
Starting with version 1.1.0 CA/CRL certificates, private keys, passphrases and database passwords can be stored in Hashicorp Vault storage.

It is the responsibility of the caller to provide a valid Vault token. The Vault token will be obtained (in this order) from:

* environment variable `VAULT_TOKEN`
* read from file `${HOME}/.vault_token` (`vault login` / `vault token renew` will store the current token in this file)

Only the [Key / Value Secrets Engine](https://www.vaultproject.io/docs/secrets/kv/index.html) is supported.

Vault URL can be provided as `scheme://vault.server:vault_port/path/to/kv/location`. Supported `scheme` values are:

| Scheme | Description |
|:-------|:------------|
| `vault` | Use unencrypted HTTP access |
| `http` | ***Should never be used in productive environment*** |
| `vaults` | Use HTTPS access |
| `https` | If `vault_insecure_ssl` is set to `false` (the default) the SSL certificate will be validated |
|         | and the signing CA of the server certificate must be present in the trusted certificate store |
|         | of the operating system |

The name of the keys are hard coded as:

| Key | Description |
|:----|:------------|
| `ca_public_key` | Public key of the CA certificate |
| `ca_private_key` | Base64 encoded encrypted private key of the CA certificate in PKCS8 format |
| `ca_passphrase` | Passphrase of the encrypted CA private key |
| `crl_public_key` | Public key of the CRL certificate |
| `crl_private_key` | Base64 encoded encrypted private key of the CRL certificate in PKCS8 format |
| `crl_passphrase` | Passphrase of the encrypted CRL private key |
| `database_passphrase` | Passphrase for database access |

### Configuration file
#### Global section
The `global` section contains general configuration settings. Depending on the purpose, not all of the options must be set. (For instance a configuration for a dedicated system to generate the revocation list doesn't need the CA key settings.)

| Configuration variable | Description |
|:-----------------------|:------------|
| `add_ca_issuer_uris` | White space separated list of CA issuer URIs to add to every signed certificate signing request|
| `add_ocsp_uris` | White space separated list of OCSP URIs to add to every signed certificate signing request|
| `auto_renew_start_period` | For auto renewable certificates, the auto renewable will be run if less then `auto_renew_start_period` days are left til expiration |
| `backend` | Database backend to use. Possible options are |
|   | `mysql` - MySQL |
|   | `pgsql` - PostgreSQL |
|   | `sqlite3` - SQLite3 |
| `ca_public_key` | Absolute path or Vault URL to the public key of the CA certificate |
| `ca_private_key` | Absolute path or Vault URL to the private key of the CA certificate |
| `ca_passphrase` | The passphrase or Vault URL to decrypt the private key of the CA certificate |
| `default_site` | Load configuration from this site if no site has been specified (`--site` option) |
| `digest` | Default message digest to use for certificate signing. See `dgst(1)` for a complete list of supported message digest algorithm of the current OpenSSL installation |
| `serial_number` | Method to generate new serial numbers, possible options are: |
|   | `random `- Use random serial numbers |
|   | `increment` - Increment the last serial number |
|   | *Default:* `random` |
| `crl_public_key` | The absolute path or Vault URL to the public key for the certificate to sign the certificate revocation list. This can be the same as the CA certificate but it best practices recommend a separate certificate with a shorter validity period |
| `crl_private_key` | The absolute path or Vault URL to the private key for the certificate to sign the certificate revocation list. This can be the same as the CA certificate but it best practices recommend a separate certificate with a shorter validity period |
| `crl_passphrase` | The passphrase or Vault URL to decrypt the private key of the certificate used to sign the revocation list|
| `crl_validity_period` | The number of days before the next CRL is due |
| `list_as_hex` | Show serial numbers as hexadecimal (*Default:* `false` |
| `ocsp_public_key` | Absolute path or Vault URL to the public key of the OCSP signing certificate |
| `ocsp_private_key` | Absolute path or Vault URL to the private key of the OCSP signing certificate |
| `ocsp_passphrase` | The passphrase or Vault URL to decrypt the private key of the OCSP signing certificate |
| `ocsp_digest` | Default message digest to use for certificate signing. See `dgst(1)` for a complete list of supported message digest algorithm of the current OpenSSL installation |
|               | *Default:* `sha1` |
| `ocsp_uri` | URI to listen for OCSP requests as defined in the `Authority Information Access` field of the certificate |
| `ocsp_server_public_key` | If the scheme of the `ocsp_uri` is `https` the file containing the server certificates public key |
| `ocsp_server_private_key` | If the scheme of the `ocsp_uri` is `https` the file containing the server certificates *unencrypted* private key |
| `sites` | Space separated list of `<sitename>:/path/to/config.for.site` |
| `validity_period` | The number of days to make a certificate valid |
| `vault_insecure_ssl` | Don't validate SSL certificate of the Vault server |
|   | *Default:* `false`
| `vault_timeout` | Timeout in seconds for Vault requests |
|   |  *Default:* 5 |

#### Logging section
The logging section is optional and contains options for logging. A unique user defined string can be used for each `logname`.
The format should be all lowercase letters and numbers and underscores (`_`). If no logging section has been given (or it is empty) the default will be used (Destination: `syslog`, Facility: `user`).

#### MySQL configuration
The `mysql` section contains configuration settings for the MySQL bkend. At least `host`, `database`, `user` and `password` must be set.

| Configuration variable | Description |
|:-----------------------|:------------|
| `host` | The hostname or IP address to connect to |
| `port` | The port MySQL is running on (*Default:* 3306) |
| `database` | Name of the database to connect to |
| `user` | The user name for the database connection |
| `passphrase` | The password or Vault URL for the user of the database connection |
| `sslcacert` | Path to the CA public key file (PEM format) |
| `sslcert` | Path to the client certificate (PEM format) for client authentication with SSL certificate |
| `sslkey` | Path to the client certificate key file (PKCS#1 format) for client authentication with SSL certificate |

#### PostgreSQL configuration
The `pgsql` section contains configuration settings for the PostgreSQL backend. At least `host`, `database`, `user` and `password` must be set.

| Configuration variable | Description |
|:-----------------------|:------------|
| `host` | The hostname or IP address to connect to |
| `port` | The port PostGres is running on (usually 5432) |
| `database` | Name of the database to connect to |
| `user` | The user name for the database connection |
| `passphrase` | The password or Vault URL for the user of the database connection |
| `sslmode` | SSL protection level 3). Valid values are:
|   | `disable` - Don't use SSL at all |
|   | `require` - Use SSL but don't check the server certificate |
|   | `verify-ca` - Use SSL and check if the server certificate has been signed by the correct CA |
|   | `verify-full` - Use SSL and check the server name in the certificate and the signing CA of the server certificate |
| `sslcacert` | Path to the CA public key file (PEM format) |
| `sslcert` | Path to the client certificate (PEM format) for client authentication with SSL certificate |
| `sslkey` | Path to the client certificate key file (PKCS#1 format) for client authentication with SSL certificate |

#### SQLite3 configuration
The `sqlite3` section contains configuration settings for the SQLite3 backend. The `database` options is mandatory.

| Configuration variable | Description |
|:-----------------------|:------------|
| `database`| The absolute path to the SQLite3 database file |

### Environment variables
In addition to the configuration file environment variables can be used. Configuration variables from environment variables replace values from configuration file.

| Environment variable | Configuration file section | Configuration file variable |
|:---------------------|:---------------------------|:----------------------------|
| `PKIDB_GLOBAL_ADD_CA_ISSUER_URIS` | `global` | `add_ca_issuer_uris` |
| `PKIDB_GLOBAL_ADD_OCSP_URIS` | `global` | `add_ocsp_uris` |
| `PKIDB_GLOBAL_AUTO_RENEW_START_PERIOD` | `global` | `auto_renew_start_period` |
| `PKIDB_GLOBAL_BACKEND` | `global` | `backend` |
| `PKIDB_GLOBAL_CA_CERTIFICATE` | `global` | `ca_certificate` |
| `PKIDB_GLOBAL_CA_PASSPHRASE` | `global` | `ca_passphrase` |
| `PKIDB_GLOBAL_CA_PRIVATE_KEY` | `global` | `ca_private_key` |
| `PKIDB_GLOBAL_CA_PUBLIC_KEY` | `global` | `ca_public_key` |
| `PKIDB_GLOBAL_CRL_CERTIFICATE` | `global` | `crl_certificate` |
| `PKIDB_GLOBAL_CRL_PASSPHRASE` | `global` | `crl_passphrase` |
| `PKIDB_GLOBAL_CRL_PRIVATE_KEY` | `global` | `crl_private_key` |
| `PKIDB_GLOBAL_CRL_PUBLIC_KEY` | `global` | `crl_public_key` |
| `PKIDB_GLOBAL_CRL_VALIDITY_PERIOD` | `global` | `crl_validity_period` |
| `PKIDB_GLOBAL_DEFAULT_SITE` | `global` | `default_site` |
| `PKIDB_GLOBAL_DIGEST` | `global` | `digest` |
| `PKIDB_GLOBAL_LIST_AS_HEX` | `global` | `list_as_hex` |
| `PKIDB_GLOBAL_OCSP_CERTIFICATE` | `global` | `ocsp_certificate` |
| `PKIDB_GLOBAL_OCSP_DIGEST` | `global` | `ocsp_digest` |
| `PKIDB_GLOBAL_OCSP_PASSPHRASE` | `global` | `ocsp_passphrase` |
| `PKIDB_GLOBAL_OCSP_PRIVATE_KEY` | `global` | `ocsp_private_key` |
| `PKIDB_GLOBAL_OCSP_PUBLIC_KEY` | `global` | `ocsp_public_key` |
| `PKIDB_GLOBAL_OCSP_SERVER_PRIVATE_KEY` | `global` | `ocsp_server_private_key` |
| `PKIDB_GLOBAL_OCSP_SERVER_PUBLIC_K` | `global` | `ocsp_server_public_key` |
| `PKIDB_GLOBAL_OCSP_URI` | `global` | `ocsp_uri` |
| `PKIDB_GLOBAL_SERIAL_NUMBER` | `global` | `serial_number` |
| `PKIDB_GLOBAL_SITES` | `global` | `sites` |
| `PKIDB_GLOBAL_VALIDITY_PERIOD` | `global` | `validity_period` |
| `PKIDB_GLOBAL_VAULT_INSECURE_SSL` | `global` | `vault_insecure_ssl` |
| `PKIDB_GLOBAL_VAULT_TIMEOUT` | `global` | `vault_timeout` |
| `PKIDB_MYSQL_DATABASE` | `mysql` | `database` |
| `PKIDB_MYSQL_HOST` | `mysql` | `host` |
| `PKIDB_MYSQL_PASSPHRASE` | `mysql` | `passphrase` |
| `PKIDB_MYSQL_PORT` | `mysql` | `port` |
| `PKIDB_MYSQL_SSLCACERT` | `mysql` | `sslcacert` |
| `PKIDB_MYSQL_SSLCERT` | `mysql` | `sslcert` |
| `PKIDB_MYSQL_SSLKEY` | `mysql` | `sslkey` |
| `PKIDB_MYSQL_SSLMODE` | `pgsql` | `sslmode` |
| `PKIDB_MYSQL_USER` | `mysql` | `user` |
| `PKIDB_PGSQL_DATABASE` | `pgsql` | `database` |
| `PKIDB_PGSQL_HOST` | `pgsql` | `host` |
| `PKIDB_PGSQL_PASSPHRASE` | `pgsql` | `passphrase` |
| `PKIDB_PGSQL_PORT` | `pgsql` | `port` |
| `PKIDB_PGSQL_SSLCACERT` | `pgsql` | `sslcacert` |
| `PKIDB_PGSQL_SSLCERT` | `pgsql` | `sslcert` |
| `PKIDB_PGSQL_SSLKEY` | `pgsql` | `sslkey` |
| `PKIDB_PGSQL_SSLMODE` | `pgsql` | `sslmode` |
| `PKIDB_PGSQL_USER` | `pgsql` | `user` |
| `PKIDB_SQLITE3_DATABASE` | `sqlite3` | `database` |

----

# Changes from `python-pkidb`
## Getopt short options are no longer supported
Due to the switch to Go! the command-line parsing changes to standard Go! behavior and as a consequence getopt short options are no longer supported.

## Date format
If dates are specified the format must **always** be a ASN1 GERNERALIZEDTIME string in the format `YYYYMMDDhhmmssZ`

## Basic constraints
[RFC 5280 - Section 4.2.1.9](https://tools.ietf.org/html/rfc5280#section-4.2.1.9) only defines two basic constraints - `CA` and `pathlen` - and doesn't define the criticality of the basic constraints. As a consequence the critical flag has been removed for basic constraints and basic constraints are limited to `CA` and `pathlen`.

Additionally supplied `pathlen` will not be set (and an error occurs) if `CA` is not set and key usage does not include `keyCertSign`.
This is mandated by RFC 5280: _<u>CAs MUST NOT include the pathLenConstraint field unless the CA boolean is asserted and the key usage extension asserts the keyCertSign bit</u>._)

## Subject alternative names
The criticality of the subject alternative names depend on the subject fields (see [RFC 5280 - Section 4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)). To ensure generation of valid (according to RFC 5280) certificates the possibility to define the criticality has been removed.

## Key usage flags are always marked as critical
Key usage flags (`pkidb sign --keyusage=...`) are **_always_** defined as CRITICAL as defined in [RFC 5280 - Section 4.2.1.3](https://tools.ietf.org/html/rfc5280#section-4.2.1.3) (_<u>When present, conforming CAs SHOULD mark this extension as critical</u>_).

Hence the option to set the criticality flag of the key usage flags has been removed.

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

## `healthcheck` command has been removed
Starting with version 1.2.0 the `healthcheck` command has been removed.

----

# Migration from `python-pkidb`
## Encrypted private keys
Due to the inability of Golang to handle encrypted private SSL keys in PEM format (see [crypto/tls: needs a convenience function for reading encrypted keys](https://github.com/golang/go/issues/6722))
all encrypted private keys (for the CA and/or CRL signing) must be converted the PKCS8 format, encrypted with PKCS5 v2 algorithm and stored in the DER format.
This can be done by using `openssl pksc8` e.g.:

`openssl pkcs8 -topk8 -in ca_private.key -out ca_private.der -outform DER`

:heavy_exclamation_mark: <u>**Be very careful when using copy&paste to pass in the password, because `openssl` may use the line break in the password of the PKCS8 file**</u> :heavy_exclamation_mark:

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

Instead of:

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

This is a known bug - [encoding/asn1: valid GeneralizedTime not parsed #15842](https://github.com/golang/go/issues/15842) - hopefully fixed ino 1.15.

Luckily the impact is limited only to the renewal of such a certificate (e.g. `pkidb renew ...`).

#### No support for nonce extension in OCSP
The Go! implementation for OCSP doesn't support the (optional) nonce extension, see [x/crypto/ocsp: request and response extensions are not supported #20001](https://github.com/golang/go/issues/20001). If OCSP is used with the OpenSSL command line (`openssl ocsp ...`) the warning about the missing nonce (`WARNING: no nonce in response`) can be safely ignored.

