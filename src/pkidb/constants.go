package main

import (
	"crypto/x509"
)

const name string = "pkidb"
const version string = "1.0.0-2019.12.01"

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

// DefaultConfigurationFile - default configuration file if not specified otherwise
const DefaultConfigurationFile = "/etc/pkidb/config.ini"

// HelpText - Help text
const HelpText = `Usage: %s [-c <cfg>|--config=<cfg>] [-h|--help] <command> [<commandoptions>]

  -V                                        Shows version.
  --version

  -c <cfg>                                  Use configuration file instead of the default
  --config=<cfg>                            Default: %s

  -s <site>                                 Use configuration for <site>
  --site=<site>                             Default: Use global configuration or default site (if set and not empty)

  -h                                        This text
  --help

  Commands:

   add-dummy                                Add a dummy certificate identified by the serial number.
                                            If the serial number is not given on the command line it will be
                                            read from standard input.
                                            This can be used if the certificate has been issued but the certificate
                                            file is not present (e.g. during a migration) but the serial number
                                            and optionally the start date, end date or subject is known.

     -S <subject>                           Certificate subject.
     --subject=<subject>

     -s <start>                             Start of the certificates validity period.
     --start=<start>                        <start> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ

     -e <end>                               End of the certificates validity period.
     --end=<end>                            <end> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ

   backup                                   Dumps the content of the backend database in JSON format.
                                            This can be used to backup the PKI database and is the only
                                            supported way to migrate between different backend types.
                                            If no output file (option -o) has been given it will be written
                                            to standard output.

     -o <output>                            Write database dump to <output> instead of standard out.
     --output=<output>

   delete                                   Deletes a certificate identified by the serial number.
                                            If the serial number is not given on the command line it will be
                                            read from standard input.

   export                                   Dumps base64 encoded X509 data of a certificate (aka PEM format).
                                            The serial number of the certificate must be given.
                                            If not given it will be read from the standard input.
                                            The certificate will be written to standard output or to a file if
                                            the -o option is used.

     -o <output>                            Write certificate to <output> instead of standard out.
     --output=<output>

   gencrl                                   Generate certificate revocation list containing information about revoked
                                            certificates. The certificate revocation list will be written to standard
                                            output or to a file if -o is used.

     -o <output>                            Write revocation list to <output> instead of standard output.
     --output=<output>

   healthcheck                              Verify integrity of the stored certifiate data.

   -f                                       Fix errors. Stored data will be replaced with data from the certifiate
   --fix                                    stored in the database.

   housekeeping                             General "housekeeping". Checking all certificates in the database
                                            for expiration, renew auto renewable certificates (if option -a is used).
                                            This should be run at regular intervals.

     -a                                     Renew auto renawable certificates that will expire.
     --auto-renew

     -p <period>                            New validity period for auto renewed certificate.
     --period=<period>                      Default is the value given on import that has been stored in the backend.

   import                                   Import a certificate. If a file name is given it will be read
                                            from the file, otherwise it will be read from standard input.

     -a                                     Mark certificate as autorenwable.
     --auto-renew                           The "housekeeping" command will take care of this

     -c <csr>                               Certificate signing request used for certificate
     --csr=<csr>                            creation. Optional.

     -d <delta_period>                      For auto renewable certificates the auto renew process starts if the time
     --delta=<delta_period>                 til expiration is less than <delta_period> days.

     -p <period>                            New validity period for auto renewed certificate.
     --period=<period>                      Default is the value given in the configuration file as validity_period.

     -r <reason>,<time>                     Mark certificate as revoked. Optional.
     --revoked=<reason>,<time>              <time> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ
                                            <reason> can be one of:
                                            unspecified, keyCompromise, CACompromise, affiliationChanged,
                                            superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
                                            removeFromCRL, aACompromise

   list                                     List serial numbers of certificates.
                                            The list will be written to standard out if the option -o is not used.

     -e                                     List serial numbers of expired certificates.
     --expired

     -i                                     List serial numbers of invalid certificates.
     --invalid                              Certficates are considered invalid if their notBefore time is in the future.

     -h                                     Print serial number as hexadecimal number.
     --hex

     -o <output>                            Write serial numbers of listed certificate to <output> instead to standard
     --output=<output>                      output.

     -r                                     List serial numbers of revoked certificates.
     --revoked

     -t                                     List "certificates" marked as temporary,
     --temporary                            Temporary certficates are dummy settings used to "lock" serial numbers
                                            during signing of a certificate signing request.

     -v                                     List serial numbers of valid certificates.
     --valid                                A certificates is considered valid if it is not temporary, not revoked,
                                            the validity period (notBefore .. notAfter) has started and the
                                            certificates is not expired.

   renew                                    Renew a cerificate. The serial number of the certificate must be given.
                                            If not given it will be read from the standard input.
                                            The new certificate will be written to standard output or to a file if
                                            the -o option is used.

     -o <output>                            Write new certificate to <output> instead of standard out
     --output=<output>

     -p <period>                            New validity period for renewed certificate.
     --period=<period>                      Default <validity_period> from configuration file.

   restore                                  Restores database from a JSON file generated with the backup command.
                                            If the filename of the input data is given on the command line it
                                            will be read, otherwise input will be read from standard input

   revoke                                   Revoke a certificate. Serial number of the certificate to revoke must
                                            be used. If not given on the command line it will be read from
                                            stdin.

     -f                                     Revoke certificate by it's serial number event it is not present in the
     --force                                database. A dummy entry will be inserted in the database and marked as
                                            revoked.

     -r <reason>                            Set revocation reason for certificate.
     --reason=<reason>                      <reason> can be one of:
                                            unspecified, keyCompromise, CACompromise, affiliationChanged,
                                            superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
                                            removeFromCRL, aACompromise
                                            If no reasen is given, the default "unspecified" is used.

     -R <date>                              Set revocation date for certificate.
     --revocation-date=<date>               <revdate> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                            string in the format YYYYMMDDhhmmssZ.
                                            If not given, the current date will be used.

   search                                   Search certificate subject for a given string. Search string can be given
                                            on the command line. If omitted it will be read from standard input.
                                            SQL wildcards like %% can be used. The serial numbers matching the search
                                            will be printed to standard output.

   set                                      Modify meta data of a certificate identified by the serial number.
                                            The serial number of the certificate must be given on the command line or
                                            will be read from the standard input.

     -A                                     Mark a certificate as auto renewable.
     --auto-renew

     -P <period>                            Set auto renew start period in days. If there are less than <period> days
     --auto-renew-start-period=<period>     left until certificate expiration it will be renewed. The "housekeeping"
                                            command will renew the certificate.

     -V                                     Renew the certificate for <period> days. If not specified the setting
     --auto-renew-validity-period=<period>  from the configuration file will be used.

     -a                                     Remove auto renewable flag from certificate meta data.
     --no-auto-renew

     -c <signing_request>                   Set certificate signing request.
     --csr=<signing_request>

   show                                     Shows information of a certificate identified by the serial number.
                                            The serial number of the certificate must be given on the command line or
                                            will be read from the standard input.
                                            The certificate information will be written to standard output or to a
                                            file if the -o option is used.

     -o <output>                            Write new certificate information to <output> instead of standard output.
     --output=<output>

   sign                                     Sign a certificate signing request. If a file name is given it will be
                                            read, otherwise it will be read from stdin. Output will be written to
                                            stdout or to a file if -o option is used.

     -E <extdata>                           X509 extension. Can be repeated for multiple extensions.
     --extension=<extdata>                  Parameter <extdata> is a comma separated list of:
                                            <name> - Name of the X509 extension
                                            <critical> - Critical flag. 0: False, 1: True
                                            <subject> - Subject, is usually empty
                                            <issuer> - Issuer, is usually empty
                                            <data> - data of the extension

     -K [critical:]:<flags>                 Comma separated list of extended key usage bits.
     --extended-keyusage=[critical:]<flags> Prefix critical: can be used to set the critical flag.
                                            Additionally dotted numeric OID are allowed too, e.g. 1.2.3.4.5
                                            Known extended key usage bits are (defined in RFC 5280):
                                            serverAuth, clientAuth, codeSigning, emailProtection, timeStamping,
                                            msCodeInd, msCodeCom, msCTLSign, msSGC, msEFS, nsSGC


     -S [critical:]<san>                    subjectAltName extension. Prefix critical: can be used to set the critical
     --san=[critical:]<san>                 flag on the alternate name list (default: False).
                                            This is the same as --extension=subjectAltName,[0|1],,,<san>
                                            but as using the subjectAltName extension is the
                                            most common extension this is an extra option.

     -a                                     Mark certificate as auto renewable.
     --auto-renew                           The "housekeeping" command will take care of this

     -b critical:<data>                     Set basic constraints Prefix critical: can be used to set the critical
     --basic-constraint=critical:]<data>    flag on the basic constraints, e.g. -b critical:CA:TRUE,pathlen:1 for
                                            a CA certificate with a maximal path length of 1.

     -k [critical:]<flags>                  Comma separated list of keyUsage bits. Prefix critical: can be used to set
     --keyusage=[critical:]<flags>          the critical flag. Known keyUsage bits according to RFC 5280 are:
                                            digitalSignature, nonRepudiation (or contentCommitment), keyEncipherment,
                                            dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly,
                                            decipherOnly (see RFC 5280, Section 4.2.1.3 "Key Usage" for futher details).

     -n                                     Don't store certificate data - except the serial number - in the database.
     --no-register                          The serial number is ALWAYS stored in the backend to avoid conflicting
                                            serial numbers of certificates (especially if the serial numbers are
                                            generated using "increment" strategy).

     -o <out>                               Write data to <outfile> instead of stdout
     --output=<out>

     -s <start>                             Validity of the new certificate starts in startin days.
     --start-in=<start>                     Default: now

     -t <template>                          Use a template file for certificate signing.
     --template=<template>

     -v <validfor>                          New certificate will be valid for validfor days.
     --valid-for=<validfor>                 Default ist the defined validity_period in the configuration or the
                                            template file.

   statistics                               Print small summary of stored certificates. Output will be written to
                                            stdout.
`
