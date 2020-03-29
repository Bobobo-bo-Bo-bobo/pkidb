package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log/syslog"
	"math/big"
)

const name = "pkidb"
const version = "1.2.0-20200329"
const _url = "https://git.ypbind.de/cgit/pkidb/"

var userAgent = fmt.Sprintf("%s/%s (%s)", name, version, _url)

// DummyCertificateSubject - subject for dummy entry
const DummyCertificateSubject = "dummy entry"

// OIDMap - map OID to name (see https://oidref.com/)
var OIDMap = map[string]string{
	"1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
	"1.3.6.1.5.5.7.1.2": "biometricInfo",
	"1.3.6.1.5.5.7.1.3": "qcStatements",
	"1.3.6.1.5.5.7.1.4": "auditIdentity",
	//    "1.3.6.1.5.5.7.1.5": "5",
	"1.3.6.1.5.5.7.1.6": "aaControls",
	//    "1.3.6.1.5.5.7.1.7": "7",
	//    "1.3.6.1.5.5.7.1.8": "8",
	//    "1.3.6.1.5.5.7.1.9": "9",
	"1.3.6.1.5.5.7.1.10": "proxying",
	"1.3.6.1.5.5.7.1.11": "subjectInfoAccess",
	"1.3.6.1.5.5.7.1.12": "id-pe-logotype",
	"1.3.6.1.5.5.7.1.13": "id-pe-wlanSSID",
	"1.3.6.1.5.5.7.1.14": "id-pe-proxyCertInfo",
	//    "1.3.6.1.5.5.7.1.15": "15",
	//    "1.3.6.1.5.5.7.1.16": "16",
	//    "1.3.6.1.5.5.7.1.17": "17",
	//    "1.3.6.1.5.5.7.1.18": "18",
	//    "1.3.6.1.5.5.7.1.19": "19",
	//    "1.3.6.1.5.5.7.1.20": "20",
	"1.3.6.1.5.5.7.1.21": "id-pe-clearanceConstraints",
	"1.3.6.1.5.5.7.1.23": "nsa",
	"1.3.6.1.5.5.7.1.25": "securityInfo",
	"2.5.29.1":           "authorityKeyIdentifier (deprecated)",
	"2.5.29.2":           "keyAttributes",
	"2.5.29.3":           "certificatePolicies (obsolete)",
	"2.5.29.4":           "keyUsageRestriction",
	"2.5.29.5":           "policyMapping",
	"2.5.29.6":           "subtreesConstraint",
	"2.5.29.7":           "subjectAltName (obsolete)",
	"2.5.29.8":           "issuerAltName (obsolete)",
	"2.5.29.9":           "subjectDirectoryAttributes",
	"2.5.29.10":          "basicConstraints (deprecated)",
	//    "2.5.29.11": "11",
	//    "2.5.29.12": "12",
	//    "2.5.29.13": "13",
	"2.5.29.14": "subjectKeyIdentifier",
	"2.5.29.15": "keyUsage",
	"2.5.29.16": "privateKeyUsagePeriod",
	"2.5.29.17": "subjectAltName",
	"2.5.29.18": "issuerAltName",
	"2.5.29.19": "basicConstraints",
	"2.5.29.20": "cRLNumber",
	"2.5.29.21": "reasonCode",
	"2.5.29.22": "expirationDate",
	"2.5.29.23": "instructionCode",
	"2.5.29.24": "invalidityDate",
	"2.5.29.25": "cRLDistributionPoints (obsolete)",
	"2.5.29.26": "issuingDistributionPoint (obsolete)",
	"2.5.29.27": "deltaCRLIndicator",
	"2.5.29.28": "issuingDistributionPoint",
	"2.5.29.29": "certificateIssuer",
	"2.5.29.30": "nameConstraints",
	"2.5.29.31": "cRLDistributionPoints",
	"2.5.29.32": "certificatePolicies",
	"2.5.29.33": "policyMappings",
	"2.5.29.34": "policyConstraints (deprecated)",
	"2.5.29.35": "authorityKeyIdentifier",
	"2.5.29.36": "policyConstraints",
	"2.5.29.37": "extKeyUsage",
	"2.5.29.38": "authorityAttributeIdentifier",
	"2.5.29.39": "roleSpecCertIdentifier",
	"2.5.29.40": "cRLStreamIdentifier",
	"2.5.29.41": "basicAttConstraints",
	"2.5.29.42": "delegatedNameConstraints",
	"2.5.29.43": "timeSpecification",
	"2.5.29.44": "cRLScope",
	"2.5.29.45": "statusReferrals",
	"2.5.29.46": "freshestCRL",
	"2.5.29.47": "orderedList",
	"2.5.29.48": "attributeDescriptor",
	"2.5.29.49": "userNotice",
	"2.5.29.50": "sOAIdentifier",
	"2.5.29.51": "baseUpdateTime",
	"2.5.29.52": "acceptableCertPolicies",
	"2.5.29.53": "deltaInfo",
	"2.5.29.54": "inhibitAnyPolicy",
	"2.5.29.55": "targetInformation",
	"2.5.29.56": "noRevAvail",
	"2.5.29.57": "acceptablePrivilegePolicies",
	"2.5.29.58": "id-ce-toBeRevoked",
	"2.5.29.59": "id-ce-RevokedGroups",
	"2.5.29.60": "id-ce-expiredCertsOnCRL",
	"2.5.29.61": "indirectIssuer",
	"2.5.29.62": "id-ce-noAssertion",
	"2.5.29.63": "id-ce-aAissuingDistributionPoint",
	"2.5.29.64": "id-ce-issuedOnBehaIFOF",
	"2.5.29.65": "id-ce-singleUse",
	"2.5.29.66": "id-ce-groupAC",
	"2.5.29.67": "id-ce-allowedAttAss",
	"2.5.29.68": "id-ce-attributeMappings",
	"2.5.29.69": "id-ce-holderNameConstraints",
}

// OIDCRLReason - OID for CRLReason - see RFC 5280, Section 5.3.1 - Reason Code
const OIDCRLReason = "2.5.29.21"

// RevocationReasonMap - map revocation reason to db values which are the same as CRLReason values as defined in RFC 5280, Section 5.3.1 - Reason Code
var RevocationReasonMap = map[string]int{
	"unspecified":          0,
	"keycompromise":        1,
	"cacompromise":         2,
	"affiliationchanged":   3,
	"superseded":           4,
	"cessationofoperation": 5,
	"certificatehold":      6,
	"unused":               7,
	"removefromcrl":        8,
	"privilegewithdrawn":   9,
	"aacompromise":         10,
}

// RevocationReasonReverseMap - map db values to revocation reason
var RevocationReasonReverseMap = map[int]string{
	0:  "unspecified",
	1:  "keyCompromise",
	2:  "CACompromise",
	3:  "affiliationChanged",
	4:  "superseded",
	5:  "cessationOfOperation",
	6:  "certificateHold",
	7:  "unused",
	8:  "removeFromCRL",
	9:  "privilegeWithdrawn",
	10: "aACompromise",
}

// ASN1GeneralizedTimeFormat - ASN1 generalized time format
const ASN1GeneralizedTimeFormat = "20060102150405Z"

// OutputTimeFormat - time format for output
const OutputTimeFormat = "Mon, 02 Jan 2006 15:04:05 -0700"

// SQLite3TimeFormat - date/time format for SQLite3 storage
const SQLite3TimeFormat = "2006-01-02 15:04:05-07:00"

// PgSQLTimeFormat - date/time format for PgSQL storage
const PgSQLTimeFormat = "2006-01-02T15:04:05-07:00"

// MySQLTimeFormat - date/time format for MySQL storage
const MySQLTimeFormat = "2006-01-02 15:04:05"

// DigestMap - Map OpenSSL digest to Golang x509.SignatureAlgorithm
var DigestMap = map[string]x509.SignatureAlgorithm{
	"md5":    x509.MD5WithRSA,
	"sha1":   x509.SHA1WithRSA,
	"sha256": x509.SHA256WithRSA,
	"sha384": x509.SHA384WithRSA,
	"sha512": x509.SHA512WithRSA,
}

// DigestHashMap - Map OpenSSL digest to Golang crypto.Hash
var DigestHashMap = map[string]crypto.Hash{
	"md5":    crypto.MD5,
	"sha1":   crypto.SHA1,
	"sha224": crypto.SHA224,
	"sha256": crypto.SHA256,
	"sha512": crypto.SHA512,
}

// SignatureAlgorithmNameMap - map x509.SignatureAlgorithm to (Python) names
var SignatureAlgorithmNameMap = map[x509.SignatureAlgorithm]string{
	x509.MD5WithRSA:    "md5WithRSAEncryption",
	x509.SHA1WithRSA:   "sha1WithRSAEncryption",
	x509.SHA256WithRSA: "sha256WithRSAEncryption",
	x509.SHA384WithRSA: "sha384WithRSAEncryption",
	x509.SHA512WithRSA: "sha512WithRSAEncryption",
}

// ExtendedKeyUsageMap - map extended key usage names to x509.ExtKeyUsage
var ExtendedKeyUsageMap = map[string]x509.ExtKeyUsage{
	"any":             x509.ExtKeyUsageAny,
	"serverauth":      x509.ExtKeyUsageServerAuth,
	"clientauth":      x509.ExtKeyUsageClientAuth,
	"codesigning":     x509.ExtKeyUsageCodeSigning,
	"emailprotection": x509.ExtKeyUsageEmailProtection,
	"timestamping":    x509.ExtKeyUsageTimeStamping,
	"mscodeind":       x509.ExtKeyUsageMicrosoftCommercialCodeSigning, // XXX: Is mscodecom == mscodeind ?
	"mscodecom":       x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
	"msctlsign":       x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	"mssgc":           x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	// TODO:    "msefs": x509.,  - whats this in Golang x509?
	"nssgc":          x509.ExtKeyUsageNetscapeServerGatedCrypto,
	"ocspsigning":    x509.ExtKeyUsageOCSPSigning,
	"ipsecendsystem": x509.ExtKeyUsageIPSECEndSystem,
	"ipsectunnel":    x509.ExtKeyUsageIPSECTunnel,
	"ipsecuser":      x509.ExtKeyUsageIPSECUser,
}

// KeyUsageMap - map key usage strings to x509.KeyUsage
var KeyUsageMap = map[string]x509.KeyUsage{
	"digitalsignature":  x509.KeyUsageDigitalSignature,
	"nonrepudiation":    x509.KeyUsageContentCommitment,
	"contentcommitment": x509.KeyUsageContentCommitment,
	"keyencipherment":   x509.KeyUsageKeyEncipherment,
	"dataencipherment":  x509.KeyUsageDataEncipherment,
	"keyagreement":      x509.KeyUsageKeyAgreement,
	"keycertsign":       x509.KeyUsageCertSign,
	"crlsign":           x509.KeyUsageCRLSign,
	"encipheronly":      x509.KeyUsageEncipherOnly,
	"decipheronly":      x509.KeyUsageDecipherOnly,
}

// MaximumSerialNumberString - maximum serial number as defined in RFC 3280
//   Note: RFC 3280 - 4.1.2.2  Serial number (see https://www.ietf.org/rfc/rfc3280.txt) states:
//
// 4.1.2.2  Serial number
//
//    The serial number MUST be a positive integer assigned by the CA to
//    each certificate.  It MUST be unique for each certificate issued by a
//    given CA (i.e., the issuer name and serial number identify a unique
//    certificate).  CAs MUST force the serialNumber to be a non-negative
//    integer.
//
//    Given the uniqueness requirements above, serial numbers can be
//    expected to contain long integers.  Certificate users MUST be able to
//    handle serialNumber values up to 20 octets.  Conformant CAs MUST NOT
//    use serialNumber values longer than 20 octets.
//
//    Note: Non-conforming CAs may issue certificates with serial numbers
//    that are negative, or zero.  Certificate users SHOULD be prepared to
//    gracefully handle such certificates.
//
//
//  -> so 0x7fffffffffffffff is the maximum serial number because of "Certificate users MUST be able to
//     handle serialNumber values up to 20 octets"
const MaximumSerialNumberString = "0x7fffffffffffffff"

// MaximumSerialNumber -  maximum serial number as defined in RFC 3280
var MaximumSerialNumber *big.Int

// DefaultConfigurationFile - default configuration file if not specified otherwise
const DefaultConfigurationFile = "/etc/pkidb/config.ini"

// EnvironmentConfigMap - Map environment variables into their configuration sections
var EnvironmentConfigMap = map[string]EnvConfig{
	"PKIDB_GLOBAL_AUTO_RENEW_START_PERIOD": EnvConfig{Section: "global", ConfigKey: "auto_renew_start_period"},
	"PKIDB_GLOBAL_BACKEND":                 EnvConfig{Section: "global", ConfigKey: "backend"},
	"PKIDB_GLOBAL_CA_CERTIFICATE":          EnvConfig{Section: "global", ConfigKey: "ca_certificate"},
	"PKIDB_GLOBAL_CA_PASSPHRASE":           EnvConfig{Section: "global", ConfigKey: "ca_passphrase"},
	"PKIDB_GLOBAL_CA_PRIVATE_KEY":          EnvConfig{Section: "global", ConfigKey: "ca_private_key"},
	"PKIDB_GLOBAL_CA_PUBLIC_KEY":           EnvConfig{Section: "global", ConfigKey: "ca_public_key"},
	"PKIDB_GLOBAL_CRL_CERTIFICATE":         EnvConfig{Section: "global", ConfigKey: "crl_certificate"},
	"PKIDB_GLOBAL_CRL_DIGEST":              EnvConfig{Section: "global", ConfigKey: "crl_digest"},
	"PKIDB_GLOBAL_CRL_PASSPHRASE":          EnvConfig{Section: "global", ConfigKey: "crl_passphrase"},
	"PKIDB_GLOBAL_CRL_PRIVATE_KEY":         EnvConfig{Section: "global", ConfigKey: "crl_private_key"},
	"PKIDB_GLOBAL_CRL_PUBLIC_KEY":          EnvConfig{Section: "global", ConfigKey: "crl_public_key"},
	"PKIDB_GLOBAL_CRL_VALIDITY_PERIOD":     EnvConfig{Section: "global", ConfigKey: "crl_validity_period"},
	"PKIDB_GLOBAL_DEFAULT_SITE":            EnvConfig{Section: "global", ConfigKey: "default_site"},
	"PKIDB_GLOBAL_DIGEST":                  EnvConfig{Section: "global", ConfigKey: "digest"},
	"PKIDB_GLOBAL_LIST_AS_HEX":             EnvConfig{Section: "global", ConfigKey: "list_as_hex"},
	"PKIDB_GLOBAL_OCSP_CERTIFICATE":        EnvConfig{Section: "global", ConfigKey: "ocsp_certificate"},
	"PKIDB_GLOBAL_OCSP_DIGEST":             EnvConfig{Section: "global", ConfigKey: "ocsp_digest"},
	"PKIDB_GLOBAL_OCSP_PASSPHRASE":         EnvConfig{Section: "global", ConfigKey: "ocsp_passphrase"},
	"PKIDB_GLOBAL_OCSP_PRIVATE_KEY":        EnvConfig{Section: "global", ConfigKey: "ocsp_private_key"},
	"PKIDB_GLOBAL_OCSP_PUBLIC_KEY":         EnvConfig{Section: "global", ConfigKey: "ocsp_public_key"},
	"PKIDB_GLOBAL_SERIAL_NUMBER":           EnvConfig{Section: "global", ConfigKey: "serial_number"},
	"PKIDB_GLOBAL_SITES":                   EnvConfig{Section: "global", ConfigKey: "sites"},
	"PKIDB_GLOBAL_VALIDITY_PERIOD":         EnvConfig{Section: "global", ConfigKey: "validity_period"},
	"PKIDB_GLOBAL_VAULT_INSECURE_SSL":      EnvConfig{Section: "global", ConfigKey: "vault_insecure_ssl"},
	"PKIDB_GLOBAL_VAULT_TIMEOUT":           EnvConfig{Section: "global", ConfigKey: "vault_timeout"},
	"PKIDB_MYSQL_DATABASE":                 EnvConfig{Section: "mysql", ConfigKey: "database"},
	"PKIDB_MYSQL_HOST":                     EnvConfig{Section: "mysql", ConfigKey: "host"},
	"PKIDB_MYSQL_PASSPHRASE":               EnvConfig{Section: "mysql", ConfigKey: "passphrase"},
	"PKIDB_MYSQL_PORT":                     EnvConfig{Section: "mysql", ConfigKey: "port"},
	"PKIDB_MYSQL_SSLCACERT":                EnvConfig{Section: "mysql", ConfigKey: "sslcacert"},
	"PKIDB_MYSQL_SSLCERT":                  EnvConfig{Section: "mysql", ConfigKey: "sslcert"},
	"PKIDB_MYSQL_SSLKEY":                   EnvConfig{Section: "mysql", ConfigKey: "sslkey"},
	"PKIDB_MYSQL_SSLMODE":                  EnvConfig{Section: "pgsql", ConfigKey: "sslmode"},
	"PKIDB_MYSQL_USER":                     EnvConfig{Section: "mysql", ConfigKey: "user"},
	"PKIDB_PGSQL_DATABASE":                 EnvConfig{Section: "pgsql", ConfigKey: "database"},
	"PKIDB_PGSQL_HOST":                     EnvConfig{Section: "pgsql", ConfigKey: "host"},
	"PKIDB_PGSQL_PASSPHRASE":               EnvConfig{Section: "pgsql", ConfigKey: "passphrase"},
	"PKIDB_PGSQL_PORT":                     EnvConfig{Section: "pgsql", ConfigKey: "port"},
	"PKIDB_PGSQL_SSLCACERT":                EnvConfig{Section: "pgsql", ConfigKey: "sslcacert"},
	"PKIDB_PGSQL_SSLCERT":                  EnvConfig{Section: "pgsql", ConfigKey: "sslcert"},
	"PKIDB_PGSQL_SSLKEY":                   EnvConfig{Section: "pgsql", ConfigKey: "sslkey"},
	"PKIDB_PGSQL_SSLMODE":                  EnvConfig{Section: "pgsql", ConfigKey: "sslmode"},
	"PKIDB_PGSQL_USER":                     EnvConfig{Section: "pgsql", ConfigKey: "user"},
	"PKIDB_SQLITE3_DATABASE":               EnvConfig{Section: "sqlite3", ConfigKey: "database"},
}

const (
	// PKICertificateStatusError - error
	PKICertificateStatusError int = -2
	// PKICertificateStatusTemporary - temporary certificate
	PKICertificateStatusTemporary int = -1
	// PKICertificateStatusPending - pending certificate
	PKICertificateStatusPending int = 0
	// PKICertificateStatusValid - valid certificate
	PKICertificateStatusValid int = 1
	// PKICertificateStatusRevoked - revoked certificate
	PKICertificateStatusRevoked int = 2
	// PKICertificateStatusExpired - expired certificate
	PKICertificateStatusExpired int = 3
	// PKICertificateStatusInvalid - invalid certificate
	PKICertificateStatusInvalid int = 4
	// PKICertificateStatusDummy - dummy certificate
	PKICertificateStatusDummy int = 5
)

const (
	// LogLevelInfo - lop level info
	LogLevelInfo int = iota
	// LogLevelWarning - log level warning
	LogLevelWarning
	// LogLevelCritical - log level critical
	LogLevelCritical
)

// LogLevelMap - map log level to constants
var LogLevelMap = map[string]int{
	"info":     LogLevelInfo,
	"warn":     LogLevelWarning,
	"warning":  LogLevelWarning,
	"critical": LogLevelCritical,
}

// LogLevelSyslogPrio - map log level to syslog priority
var LogLevelSyslogPrio = map[int]syslog.Priority{
	LogLevelInfo:     syslog.LOG_INFO,
	LogLevelWarning:  syslog.LOG_WARNING,
	LogLevelCritical: syslog.LOG_CRIT,
}

// SyslogFacilityMap - map syslog facility
var SyslogFacilityMap = map[string]syslog.Priority{
	"kernel":   syslog.LOG_KERN,
	"user":     syslog.LOG_USER,
	"mail":     syslog.LOG_MAIL,
	"daemon":   syslog.LOG_DAEMON,
	"auth":     syslog.LOG_AUTH,
	"syslog":   syslog.LOG_SYSLOG,
	"lpr":      syslog.LOG_LPR,
	"news":     syslog.LOG_NEWS,
	"uucp":     syslog.LOG_UUCP,
	"cron":     syslog.LOG_CRON,
	"authpriv": syslog.LOG_AUTHPRIV,
	"ftp":      syslog.LOG_FTP,
	"local0":   syslog.LOG_LOCAL0,
	"local1":   syslog.LOG_LOCAL1,
	"local2":   syslog.LOG_LOCAL2,
	"local3":   syslog.LOG_LOCAL3,
	"local4":   syslog.LOG_LOCAL4,
	"local5":   syslog.LOG_LOCAL5,
	"local6":   syslog.LOG_LOCAL6,
	"local7":   syslog.LOG_LOCAL7,
}

// LogLevelReverseMap - reverse map constants -> log level
var LogLevelReverseMap = map[int]string{
	LogLevelInfo:     "INFO",
	LogLevelWarning:  "WARNING",
	LogLevelCritical: "CRITICAL",
}

// ListAllSerialNumbers - list all serial numbers
const ListAllSerialNumbers int = 42

// PKIStatusMap - Map status strings to values
var PKIStatusMap = map[string]int{
	"temporary": -1,
	"pending":   0,
	"valid":     1,
	"revoked":   2,
	"expired":   3,
	"invalid":   4,
	"dummy":     5,
}

// PKIReversStatusMap - Map status values to string
var PKIReversStatusMap = map[int]string{
	-1: "temporary",
	0:  "pending",
	1:  "valid",
	2:  "revoked",
	3:  "expired",
	4:  "invalid",
	5:  "dummy",
}

// HelpTextAddDummy - help text for add-dummy
const HelpTextAddDummy = `
   add-dummy                                Add a dummy certificate identified by the serial number.
                                            If the serial number is not given on the command line it will be
                                            read from standard input.
                                            This can be used if the certificate has been issued but the certificate
                                            file is not present (e.g. during a migration) but the serial number
                                            and optionally the start date, end date or subject is known.

     --subject=<subject>                    Certificate subject.

     --start=<start>                        Start of the certificates validity period.
                                            <start> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ

     --end=<end>                            End of the certificates validity period.
                                            <end> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ
`

// HelpTextBackup - help text for backup
const HelpTextBackup = `
   backup                                   Dumps the content of the backend database in JSON format.
                                            This can be used to backup the PKI database and is the only
                                            supported way to migrate between different backend types.
                                            If no output file (option -o) has been given it will be written
                                            to standard output.

     --output=<output>                      Write database dump to <output> instead of standard out.
`

// HelpTextDelete - help text for delete
const HelpTextDelete = `
   delete                                   Deletes a certificate identified by the serial number.
                                            If the serial number is not given on the command line it will be
                                            read from standard input.
`

// HelpTextExport - help text for export
const HelpTextExport = `
   export                                   Dumps base64 encoded X509 data of a certificate (aka PEM format).
                                            The serial number of the certificate must be given.
                                            If not given it will be read from the standard input.
                                            The certificate will be written to standard output or to a file if
                                            the -o option is used.

     --output=<output>                      Write certificate to <output> instead of standard out.
`

// HelpTextGenCRL - help text for gencrl
const HelpTextGenCRL = `
   gencrl                                   Generate certificate revocation list containing information about revoked
                                            certificates. The certificate revocation list will be written to standard
                                            output or to a file if -o is used.

     --output=<output>                      Write revocation list to <output> instead of standard output.
`

// HelpTextHealthcheck - help text for healthcheck
const HelpTextHealthcheck = `
   healthcheck                              Verify integrity of the stored certificate data.

   --fix                                    Fix errors. Stored data will be replaced with data from the certifiacte
                                            stored in the database.
`

// HelpTextHousekeeping - help text for housekeeping
const HelpTextHousekeeping = `
   housekeeping                             General "housekeeping". Checking all certificates in the database
                                            for expiration, renew auto renewable certificates (if option -a is used).
                                            This should be run at regular intervals.

     --auto-renew                           Renew auto renawable certificates that will expire.

     --period=<period>                      New validity period for auto renewed certificate.
                                            Default is the value given on import that has been stored in the backend.
`

// HelpTextImport - help text for import
const HelpTextImport = `
   import                                   Import a certificate. If a file name is given it will be read
                                            from the file, otherwise it will be read from standard input.

     --auto-renew                           Mark certificate as autorenwable.
                                            The "housekeeping" command will take care of this

     --csr=<csr>                            Certificate signing request used for certificate
                                            creation will be read from <csr>. Optional.

     --delta=<delta_period>                 For auto renewable certificates the auto renew process starts if the time
                                            til expiration is less than <delta_period> days.

     --period=<period>                      New validity period for auto renewed certificate.
                                            Default is the value given in the configuration file as validity_period.

     --revoked=<reason>,<time>              Mark certificate as revoked. Optional.
                                            <time> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ
                                            <reason> can be one of:
                                            unspecified, keyCompromise, CACompromise, affiliationChanged,
                                            superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
                                            removeFromCRL, aACompromise
`

// HelpTextList - help text for list
const HelpTextList = `
   list                                     List serial numbers of certificates.
                                            The list will be written to standard out if the option -o is not used.

     --expired                              List serial numbers of expired certificates.

     --invalid                              List serial numbers of invalid certificates.
                                            Certficates are considered invalid if their notBefore time is in the future.

     --hex                                  Print serial number as hexadecimal number.

     --output=<output>                      Write serial numbers of listed certificate to <output> instead to standard
                                            output.

     --revoked                              List serial numbers of revoked certificates.

     --temporary                            List "certificates" marked as temporary,
                                            Temporary certficates are dummy settings used to "lock" serial numbers
                                            during signing of a certificate signing request.

     --valid                                List serial numbers of valid certificates.
                                            A certificates is considered valid if it is not temporary, not revoked,
                                            the validity period (notBefore .. notAfter) has started and the
                                            certificates is not expired.
`

// HelpTextRenew - help text for renew
const HelpTextRenew = `
   renew                                    Renew a cerificate. The serial number of the certificate must be given.
                                            If not given it will be read from the standard input.
                                            The new certificate will be written to standard output or to a file if
                                            the -o option is used.

     --output=<output>                      Write new certificate to <output> instead of standard out

     --period=<period>                      New validity period for renewed certificate.
                                            Default <validity_period> from configuration file.
`

// HelpTextRestore - help text for restore
const HelpTextRestore = `
   restore                                  Restores database from a JSON file generated with the backup command.
                                            If the filename of the input data is given on the command line it
                                            will be read, otherwise input will be read from standard input.
`

// HelpTextRevoke - help text for revoke
const HelpTextRevoke = `
   revoke                                   Revoke a certificate. Serial number of the certificate to revoke must
                                            be used. If not given on the command line it will be read from
                                            stdin.

     --force                                Revoke certificate by it's serial number event it is not present in the
                                            database. A dummy entry will be inserted in the database and marked as
                                            revoked.

     --reason=<reason>                      Set revocation reason for certificate.
                                            <reason> can be one of:
                                            unspecified, keyCompromise, CACompromise, affiliationChanged,
                                            superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
                                            removeFromCRL, aACompromise
                                            If no reasen is given, the default "unspecified" is used.

     --revocation-date=<date>               Set revocation date for certificate.
                                            <revdate> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ.
                                            If not given, the current date will be used.
`

// HelpTextSearch - help text for search
const HelpTextSearch = `
   search                                   Search certificate subject for a given string. Search string can be given
                                            on the command line. If omitted it will be read from standard input.
                                            SQL wildcards like %% can be used. The serial numbers matching the search
                                            will be printed to standard output.
`

// HelpTextSet - help text for set
const HelpTextSet = `
   set                                      Modify meta data of a certificate identified by the serial number.
                                            The serial number of the certificate must be given on the command line or
                                            will be read from the standard input.

     --auto-renew                           Mark a certificate as auto renewable.

     --auto-renew-start-period=<period>     Set auto renew start period in days. If there are less than <period> days
                                            left until certificate expiration it will be renewed. The "housekeeping"
                                            command will renew the certificate.

     --auto-renew-validity-period=<period>  Renew the certificate for <period> days. If not specified the setting
                                            from the configuration file will be used.

     --no-auto-renew                        Remove auto renewable flag from certificate meta data.

     --csr=<signing_request>                Set certificate signing request, will be read from <signing_request>.
`

// HelpTextShow - help text for show
const HelpTextShow = `
   show                                     Shows information of a certificate identified by the serial number.
                                            The serial number of the certificate must be given on the command line or
                                            will be read from the standard input.
                                            The certificate information will be written to standard output or to a
                                            file if the -o option is used.

     --output=<output>                      Write new certificate information to <output> instead of standard output.
`

// HelpTextSign - help text for sign
const HelpTextSign = `
   sign                                     Sign a certificate signing request. If a file name is given it will be
                                            read, otherwise it will be read from stdin. Output will be written to
                                            stdout or to a file if -o option is used.

     --extension=<extdata>                  X509 extension. Can be repeated for multiple extensions.
                                            Parameter <extdata> is a comma separated list of:
                                            <name> - Name of the X509 extension
                                            <critical> - Critical flag. 0: False, 1: True
                                            <data> - data of the extension

     --extended-keyusage=<flags>            Comma separated list of extended key usage bits.
                                            Additionally dotted numeric OID are allowed too, e.g. 1.2.3.4.5
                                            Known extended key usage bits are (defined in RFC 5280):
                                            serverAuth, clientAuth, codeSigning, emailProtection, timeStamping,
                                            msCodeInd, msCodeCom, msCTLSign, msSGC, nsSGC


     --san <san>                             Comma separated list of subjectAltName extensions. Format of <san>
                                               is <type>:<value>. Supported <type> values are:
                                                DNS   - DNS domain name
                                                email - email address
                                                IP    - IP address (IPv4 and IPv6)
                                                URI   - URI

     --auto-renew                           Mark certificate as auto renewable.
                                            The "housekeeping" command will take care of this

     --basic-constraint=<data>              Set basic constraints. Only CA and pathlen are supported (see RFC 5280, Section 4.2.1.9)
                                            flag on the basic constraints, e.g. -b CA:TRUE,pathlen:1 for
                                            a CA certificate with a maximal path length of 1.
                                            Note: In accordance with RFC 5280 pathlen constraint can only be set if CA constraint is set
                                            and keyusage includes keyCertSign.

     --keyusage=<flags>                     Comma separated list of keyUsage bits. As defined in RFC 5280, Section 4.2.1.3
                                            the critical flag is always true.
                                            Known keyUsage bits according to RFC 5280 are:
                                            digitalSignature, nonRepudiation (or contentCommitment), keyEncipherment,
                                            dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly,
                                            decipherOnly (see RFC 5280, Section 4.2.1.3 "Key Usage" for futher details).

     --no-register                          Don't store certificate data - except the serial number - in the database.
                                            The serial number is ALWAYS stored in the backend to avoid conflicting
                                            serial numbers of certificates (especially if the serial numbers are
                                            generated using "increment" strategy).

     --output=<out>                         Write data to <outfile> instead of stdout

     --start-in=<start>                     Validity of the new certificate starts in startin days.
                                            Default: now

     --template=<template>                  Use a template file for certificate signing.

     --valid-for=<validfor>                 New certificate will be valid for validfor days.
                                            Default ist the defined validity_period in the configuration or the
                                            template file.
`

// HelpTextStatistics - help text for statistics
const HelpTextStatistics = `
   statistics                               Print small summary of stored certificates. Output will be written to
                                            stdout.
`

// HelpTextMap - map command to help text
var HelpTextMap = map[string]string{
	"add-dummy":    HelpTextAddDummy,
	"backup":       HelpTextBackup,
	"delete":       HelpTextDelete,
	"export":       HelpTextExport,
	"gencrl":       HelpTextGenCRL,
	"healthcheck":  HelpTextHealthcheck,
	"housekeeping": HelpTextHousekeeping,
	"import":       HelpTextImport,
	"list":         HelpTextList,
	"ocsp":         HelpTextOcsp,
	"renew":        HelpTextRenew,
	"restore":      HelpTextRestore,
	"revoke":       HelpTextRevoke,
	"search":       HelpTextSearch,
	"set":          HelpTextSet,
	"show":         HelpTextShow,
	"sign":         HelpTextSign,
	"statistics":   HelpTextStatistics,
}

// HelpText - Help text
const HelpText = `Usage: %s [-c <cfg>|--config=<cfg>] [-h|--help] <command> [<commandoptions>]

  --version                                 Shows version.

  --config=<cfg>                            Use configuration file instead of the default
                                            Default: %s

  --site=<site>                             Use configuration for <site>
                                            Default: Use global configuration or default site (if set and not empty)

  --help                                    This text

  Commands:
`

// HelpTextOcsp - help text for ocsp
const HelpTextOcsp = `
   ocsp                                     Start web server to process OCSP requests

     --uri=<uri>                            Listen and process OCEP requests on <uri>

`

// PublicKeyInformation - extract information from pulic key for issuerKeyHash generation
type PublicKeyInformation struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
