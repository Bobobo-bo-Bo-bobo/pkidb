CREATE TABLE IF NOT EXISTS certificate (
  -- Note: RFC 3280 (4.1.2.2  Serial number) states the serial number
  -- must be:
  --  * unique
  --  * non-negative integer
  --  * up to 20 octets (up to 2**160)
  --  * not longer than 20 octets
  --
  -- use NUMERIC as data type, it is defined as:
  --
  -- numeric  variable  user-specified precision, exact up to 131072 digits before the decimal point; up to 16383 digits after the decimal point
  -- 
  -- serial_number is the primary key
  serial_number DECIMAL(20,0) PRIMARY KEY CHECK(serial_number > 0),

  -- SSL version (Note: SSL starts version at 0)
  version INTEGER CHECK(version >= 0),

  -- set to NULL when certificate was not issued yet
  -- (csr submitted but pending)
  start_date TIMESTAMP NULL DEFAULT NULL,
  end_date TIMESTAMP NULL DEFAULT NULL,

  -- subject of certificate
  -- it is NOT unique as it may occur for current and revoked certificates
  subject TEXT NOT NULL CHECK(subject <> ''),

  -- auto renewable certificate?
  auto_renewable BOOLEAN NOT NULL DEFAULT False,
  
  -- auto renew autorenewable certificates if there is less than auto_renew_start_period days
  -- left before expiration
  auto_renew_start_period FLOAT NULL DEFAULT NULL,

  -- auto renewable certificates will be renewed for auto_renew_validity_period days
  auto_renew_validity_period FLOAT NULL DEFAULT NULL,

  -- issuer of the certificate
  -- issuer can be NULL for signing requests
  issuer TEXT CHECK(issuer <> ''),

  -- number of bits
  keysize INTEGER CHECK(keysize > 0),

  -- store fingerprints for subject data
  -- as serial_number and certificate content should be
  -- unique, enforce constraints
  -- fingerprint_* is not set (NULL) for certificates not
  -- issued yet
  fingerprint_md5 VARCHAR(32) UNIQUE DEFAULT NULL CHECK(fingerprint_md5 <> ''),
  fingerprint_sha1 VARCHAR(40) UNIQUE DEFAULT NULL CHECK(fingerprint_sha1 <> ''),

  -- certificate holds the base64 encoded public key
  -- it is NULL for pending certificates
  -- Note: MySQL can only use 767 bytes as index to ensure uniqueness
  -- Unfortunately this is not enough, so the unique constraint must
  -- be dropped for MySQL on this row.
  certificate TEXT NULL CHECK(certificate <> ''),

  -- signature algorithm, NULL is unknown signing algorithm
  signature_algorithm_id INTEGER CHECK(signature_algorithm_id > 0),

  -- x509 extensions as comma separated text because mysql can't handle arrays
  extension TEXT NULL,

  -- store index of signing request, can be NULL
  -- Note: This is NOT unique, because the same csr can be
  -- used, e.g. for reissue a certificate when the old has been
  -- revoked
  signing_request VARCHAR(128) CHECK(signing_request <> ''),

  -- state is the current state of the certificate
  -- possible values are
  -- -1 - temporary: ?
  --  0 - pending: CSR submitted but not issued yet
  --  1 - valid: certificate is valid
  --  2 - revoked: certificate has been revoked
  --  3 - expired: certificate has been expired
  --  4 - invalid: certificate is invalid (usually the validity period has not started yet)
  state INTEGER NOT NULL CHECK(state >= -1),

  -- revocation_date, not NULL when certificate has been revoked
  revocation_date TIMESTAMP NULL DEFAULT NULL,
  -- revocation_reason reason for revocation
  -- reasonFlag is defined in RFC 5280, 5.3.1. Reason Code
  -- possible values are
  --  0 - unspecified
  --  1 - keyCompromise
  --  2 - CACompromise
  --  3 - affiliationChanged
  --  4 - superseded
  --  5 - cessationOfOperation
  --  6 - certificateHold
  --  7 - unused
  --  8 - removeFromCRL
  --  9 - privilegeWithdrawn
  -- 10 - aACompromise
  revocation_reason INTEGER NULL DEFAULT NULL CHECK(revocation_reason >= 0)
);

-- create index for common queries
CREATE INDEX certificate_serial_number_idx ON certificate(serial_number) USING BTREE;
CREATE INDEX certificate_fingerprint_md5_idx ON certificate(fingerprint_md5) USING BTREE;
CREATE INDEX certificate_fingerprint_sha1_idx ON certificate(fingerprint_sha1) USING BTREE;
CREATE INDEX certificate_state_idx ON certificate(state) USING BTREE;

-- Note: MySQL can only use 767 bytes as index to ensure uniqueness
-- Unfortunately this is not enough, so the index on issuer must
-- be dropped for MySQL.
-- Futhermore MySQL imposes a limit of 65535 bytes for the table.
-- CREATE INDEX certificate_issuer_idx ON certificate(issuer) USING BTREE;

-- Note: MySQL can only use 767 bytes as index to ensure uniqueness
-- Unfortunately this is not enough, so the index on subject must
-- be dropped for MySQL.
-- Futhermore MySQL imposes a limit of 65535 bytes for the table.
-- CREATE INDEX certificate_subject_idx ON certificate(subject) USING BTREE;

-- table of certificate signing requests
CREATE TABLE IF NOT EXISTS signing_request (
  -- sha512 hash 
  hash VARCHAR(128) PRIMARY KEY CHECK(hash <> ''),

  -- certificate signinig request
  request TEXT NOT NULL CHECK(request <> '')
);

-- table of x509 extensions
CREATE TABLE IF NOT EXISTS extension (

  -- primary key is the sha512 hash of (name+criticality+data)
  hash VARCHAR(128) PRIMARY KEY,

  -- name of the x509 extension
  -- Note: On MySQL this has to be limited to 767 bytes
  -- otherwise it can't be indexed.
  name VARCHAR(767) NOT NULL CHECK(name <> ''),

  -- criticality flag of the x509 extension
  critical BOOLEAN NOT NULL DEFAULT False,

  -- subject of the extension
  subject TEXT DEFAULT NULL CHECK(subject<>''),

  -- issuer of the extension
  issuer TEXT DEFAULT NULL CHECK(issuer<>''),

  -- base64 encoded data of the extension
  data TEXT NOT NULL CHECK(data <> '')
);
CREATE INDEX extension_name_idx ON extension(name(767)) USING BTREE;

-- lookup table for signing algorithm
CREATE TABLE IF NOT EXISTS signature_algorithm (
  id SERIAL PRIMARY KEY,
  algorithm VARCHAR(128) NOT NULL CHECK(algorithm <> '')
);

