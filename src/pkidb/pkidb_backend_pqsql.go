package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/lib/pq"
	"math/big"
	"strings"
	"time"
)

// PKIDBBackendPgSQL - PgSQL database
type PKIDBBackendPgSQL struct {
	Host      string
	Port      int
	SSLMode   string
	SSLCACert string
	SSLCert   string
	SSLKey    string
	Username  string
	Password  string
	Database  string
}

// Initialise - Initialise PgSQL database connection
func (db PKIDBBackendPgSQL) Initialise(cfg *PKIConfiguration) error {
	var ok bool

	db.Host = cfg.Database.Host
	db.Port = cfg.Database.Port
	db.SSLMode = cfg.Database.SSLMode
	db.SSLCACert = cfg.Database.SSLCACert
	db.SSLCert = cfg.Database.SSLCert
	db.SSLKey = cfg.Database.SSLKey
	db.Username = cfg.Database.User
	db.Password = cfg.Database.Password
	db.Database = cfg.Database.Database

	_db, err := db.OpenDatabase(cfg)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = _db.QueryRow("SELECT 1=1").Scan(&ok)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Should NEVER happen ;)
	if !ok {
		return fmt.Errorf("%s: Unexpected result from 'SELECT 1=1;'", GetFrame())
	}

	cfg.Database.dbhandle = _db
	return nil
}

// OpenDatabase - Open database connection
func (db PKIDBBackendPgSQL) OpenDatabase(cfg *PKIConfiguration) (*sql.DB, error) {
	var _dsn string

	if db.SSLCert != "" && db.SSLKey != "" {
		_dsn = fmt.Sprintf("host=%s database=%s sslcert=%s sslkey=%s", db.Host, db.Database, db.SSLCert, db.SSLKey)
	} else {
		_dsn = fmt.Sprintf("host=%s database=%s user=%s password=%s", db.Host, db.Database, db.Username, db.Password)
	}
	// if host starts with '/' it is a socket
	if db.Host[0] != '/' {
		_dsn += fmt.Sprintf(" port=%d", db.Port)
	}

	if db.SSLMode != "" {
		switch strings.ToLower(db.SSLMode) {
		case "disable":
			fallthrough
		case "require":
			fallthrough
		case "verify-ca":
			fallthrough
		case "verify-full":
			_dsn += " sslmode=" + strings.ToLower(db.SSLMode)
		default:
			return nil, fmt.Errorf("%s: Invalid sslmode for database connection", GetFrame())
		}
	}
	if db.SSLCACert != "" {
		_dsn += " sslrootcert=" + db.SSLCACert
	}

	dbhandle, err := sql.Open("postgres", _dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	return dbhandle, nil
}

// CloseDatabase - close database connection
func (db PKIDBBackendPgSQL) CloseDatabase(h *sql.DB) error {
	var err error

	if h != nil {
		err = h.Close()
	}

	return fmt.Errorf("%s: %s", GetFrame(), err.Error())
}

// GetLastSerialNumber - get last serial number from database
func (db PKIDBBackendPgSQL) GetLastSerialNumber(cfg *PKIConfiguration) (*big.Int, error) {
	var snString string
	var sn *big.Int

	if cfg.Database.dbhandle == nil {
		return nil, fmt.Errorf("%s: Database handle is not initialised", GetFrame())
	}

	err := cfg.Database.dbhandle.QueryRow("SELECT MAX(serial_number) FROM certificate").Scan(&snString)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: No serial number found in database", GetFrame())
		}
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	sn = big.NewInt(-1)
	sn, ok := sn.SetString(snString, 0)
	if !ok {
		return nil, fmt.Errorf("%s: Can't convert serial number", GetFrame())
	}

	return sn, nil
}

// IsFreeSerialNumber - check if serial number is not used
func (db PKIDBBackendPgSQL) IsFreeSerialNumber(cfg *PKIConfiguration, serial *big.Int) (bool, error) {
	var _sn string

	sn := serial.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return false, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT serial_number FROM certificate WHERE serial_number=$1;", sn).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Commit()
			return true, nil
		}
		tx.Rollback()
		return false, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	return false, nil
}

// IsUsedSerialNumber - check if serial number is already used
func (db PKIDBBackendPgSQL) IsUsedSerialNumber(cfg *PKIConfiguration, serial *big.Int) (bool, error) {
	free, err := db.IsFreeSerialNumber(cfg, serial)
	return !free, err
}

// StoreCertificateSigningRequest - store CSR
func (db PKIDBBackendPgSQL) StoreCertificateSigningRequest(cfg *PKIConfiguration, ci *ImportCertificate) error {
	var _hash string

	sn := ci.Certificate.SerialNumber.Text(10)
	csr := ci.CSR

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(csr.Raw))

	err = tx.QueryRow("SELECT hash FROM signing_request WHERE hash=$1", _hash).Scan(&_hash)
	if err != nil {
		if err == sql.ErrNoRows {
			_, err = tx.Exec("INSERT INTO signing_request (hash, request) VALUES ($1, $2);", hash, base64.StdEncoding.EncodeToString(csr.Raw))
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}

			_, err = tx.Exec("UPDATE certificate SET signing_request=? WHERE serial_number=$1;", hash, sn)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}

			tx.Commit()
			return nil
		}
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return nil
}

// StoreCertificate - Store certificate in database
func (db PKIDBBackendPgSQL) StoreCertificate(cfg *PKIConfiguration, cert *ImportCertificate, replace bool) error {
	var algoid int

	_md5 := fmt.Sprintf("%x", md5.Sum(cert.Certificate.Raw))
	_sha1 := fmt.Sprintf("%x", sha1.Sum(cert.Certificate.Raw))
	sn := cert.Certificate.SerialNumber.Text(10)
	version := cert.Certificate.Version
	start := cert.Certificate.NotBefore
	end := cert.Certificate.NotAfter
	subject := cert.Certificate.Subject.String()
	rawCert := base64.StdEncoding.EncodeToString(cert.Certificate.Raw)
	issuer := cert.Certificate.Issuer.String()
	length := 8 * len(cert.Certificate.Signature)
	state := GetCertificateState(cert.Certificate)

	already, err := db.SerialNumberAlreadyPresent(cfg, cert.Certificate.SerialNumber)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if cert.IsDummy {
		state = PKICertificateStatusDummy
	}

	if already && !replace {
		return fmt.Errorf("%s: A certificate with this serial number already exist in the database", GetFrame())
	}

	if cert.Revoked != nil {
		state = PKICertificateStatusRevoked
	}

	if !cert.IsDummy {
		algoid, err = db.StoreSignatureAlgorithm(cfg, cert.Certificate.SignatureAlgorithm)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if already && replace {
		_, err = tx.Exec("DELETE FROM certificate WHERE serial_number=$1;", sn)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if cert.IsDummy {
		if cert.DummySubject == "" {
			_, err = tx.Exec("INSERT INTO certificate (serial_number, version, state, subject) VALUES ($1, $2, $3, $4);", sn, 0, state, DummyCertificateSubject)
		} else {
			_, err = tx.Exec("INSERT INTO certificate (serial_number, version, state, subject) VALUES ($1, $2, $3, $4);", sn, 0, state, cert.DummySubject)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		if cert.DummyNotBefore != nil {
			_, err = tx.Exec("UPDATE certificate SET start_date=? WHERE serial_number=$1;", *cert.DummyNotBefore, sn)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}

		if cert.DummyNotAfter != nil {
			_, err = tx.Exec("UPDATE certificate SET end_date=? WHERE serial_number=$1;", *cert.DummyNotAfter, sn)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}

		tx.Commit()
		return nil
	}

	_, err = tx.Exec("INSERT INTO certificate (serial_number, version, start_date, end_date, subject, fingerprint_md5, fingerprint_sha1, certificate, state, issuer, signature_algorithm_id, keysize) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);", sn, version, start, end, subject, _md5, _sha1, rawCert, state, issuer, algoid, length)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	tx.Commit()

	if cert.CSR != nil {
		err = db.StoreCertificateSigningRequest(cfg, cert)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if cert.Certificate.Extensions != nil {
		err = db.StoreX509Extension(cfg, cert, cert.Certificate.Extensions)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if cert.Certificate.ExtraExtensions != nil {
		err = db.StoreX509Extension(cfg, cert, cert.Certificate.ExtraExtensions)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if cert.Revoked != nil {
		err = db.StoreRevocation(cfg, cert.Revoked)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	if cert.AutoRenew != nil {
		err = db.StoreAutoRenew(cfg, cert.AutoRenew)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	return nil
}

// StoreAutoRenew - store auto-renew options
func (db PKIDBBackendPgSQL) StoreAutoRenew(cfg *PKIConfiguration, auto *AutoRenew) error {
	var _sn string

	sn := auto.SerialNumber.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT serial_number FROM certificate WHERE serial_number=$1;", sn).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return fmt.Errorf("%s: Certificate not found in database", GetFrame())
		}
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	_, err = tx.Exec("UPDATE certificate SET auto_renewable=$1, auto_renew_start_period=$2, auto_renew_validity_period=$3 WHERE serial_number=$4;", true, auto.AutoRenewStartPeriod, auto.ValidityPeriod, sn)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return nil
}

// StoreSignatureAlgorithm - store x509.SignatureAlgorithm name in database
func (db PKIDBBackendPgSQL) StoreSignatureAlgorithm(cfg *PKIConfiguration, algo x509.SignatureAlgorithm) (int, error) {
	name, found := SignatureAlgorithmNameMap[algo]
	if !found {
		return -1, fmt.Errorf("%s: Can't map x509.SignatureAlgorithm to a name", GetFrame())
	}

	return db.StoreSignatureAlgorithmName(cfg, name)
}

// StoreSignatureAlgorithmName - insert x509.SignatureAlgorithm name
func (db PKIDBBackendPgSQL) StoreSignatureAlgorithmName(cfg *PKIConfiguration, name string) (int, error) {
	var algoid int

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return -1, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT id FROM signature_algorithm WHERE algorithm=$1;", name).Scan(&algoid)
	if err != nil {
		if err == sql.ErrNoRows {
			_, err = tx.Exec("INSERT INTO signature_algorithm (algorithm) VALUES ($1);", name)
			if err != nil {
				tx.Rollback()
				return -1, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}

			err = tx.QueryRow("SELECT id FROM signature_algorithm WHERE algorithm=$1;", name).Scan(&algoid)
			if err != nil {
				tx.Rollback()
				return -1, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}

			tx.Commit()
			return algoid, nil
		}
		tx.Rollback()
		return -1, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	tx.Commit()

	return algoid, nil
}

// SerialNumberAlreadyPresent - check if serial number is already present in the database
func (db PKIDBBackendPgSQL) SerialNumberAlreadyPresent(cfg *PKIConfiguration, sn *big.Int) (bool, error) {
	var _sn string

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return false, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT serial_number FROM certificate WHERE serial_number=$1;", sn.Text(10)).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Commit()
			return false, nil
		}
		tx.Rollback()
		return false, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return true, nil
}

// StoreX509Extension - store x509.Extension in database
func (db PKIDBBackendPgSQL) StoreX509Extension(cfg *PKIConfiguration, cert *ImportCertificate, extensions []pkix.Extension) error {
	var _hash string
	var pkey string
	var data string
	var name string
	var found bool
	var ids = make(map[string]bool)
	var idList = make([]string, 0)

	sn := cert.Certificate.SerialNumber.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	for _, ext := range extensions {
		name, found = OIDMap[ext.Id.String()]
		if !found {
			name = ext.Id.String()
		}
		data = base64.StdEncoding.EncodeToString(ext.Value)

		// primary key is the sha512 hash of name+critical+Base64(data)
		pkey = fmt.Sprintf("%x", sha512.Sum512([]byte(name+BoolToPythonString(ext.Critical)+data)))
		err = tx.QueryRow("SELECT hash FROM extension WHERE hash=$1;", pkey).Scan(&_hash)
		if err != nil {
			if err == sql.ErrNoRows {
				_, err = tx.Exec("INSERT INTO extension (hash, name, critical, data) VALUES ($1, $2, $3, $4);", pkey, name, ext.Critical, data)
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}
				ids[pkey] = true
			} else {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
		ids[pkey] = true
	}

	for key := range ids {
		idList = append(idList, key)
	}

	// _, err = tx.Exec("UPDATE certificate SET extension=$1 WHERE serial_number=$2;", idList, sn)
	_, err = tx.Exec("UPDATE certificate SET extension=$1 WHERE serial_number=$2;", pq.Array(idList), sn)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return nil
}

// StoreRevocation - store certificate revocation
func (db PKIDBBackendPgSQL) StoreRevocation(cfg *PKIConfiguration, rev *RevokeRequest) error {
	var _sn string

	sn := rev.SerialNumber.Text(10)

	reason, found := RevocationReasonMap[strings.ToLower(rev.Reason)]
	if !found {
		return fmt.Errorf("%s: Unknown revocation reason", GetFrame())
	}

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT serial_number FROM certificate WHERE serial_number=$1;", sn).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			if rev.Force {
				// close current transaction to avoid locking issues when calling StoreCertificate
				tx.Commit()

				dummyCert := &x509.Certificate{
					SerialNumber: rev.SerialNumber,
				}
				ic := &ImportCertificate{
					Certificate:  dummyCert,
					IsDummy:      true,
					DummySubject: DummyCertificateSubject,
				}
				err = db.StoreCertificate(cfg, ic, false)
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}
			} else {
				tx.Rollback()
				return fmt.Errorf("%s: Certificate not found in database", GetFrame())
			}
		} else {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}
	tx.Commit()

	// create a new transaction
	tx, err = cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	_, err = tx.Exec("UPDATE certificate SET revocation_reason=$1, revocation_date=$2, state=$3 WHERE serial_number=$4;", reason, rev.Time, PKICertificateStatusRevoked, sn)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return nil
}

// DeleteCertificate - delete certificate from database
func (db PKIDBBackendPgSQL) DeleteCertificate(cfg *PKIConfiguration, serial *big.Int) error {
	var _sn string
	var _csr *string

	sn := serial.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT serial_number, signing_request FROM certificate WHERE serial_number=$1;", sn).Scan(&_sn, &_csr)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return fmt.Errorf("%s: Certificate not found in database", GetFrame())
		}
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	_, err = tx.Exec("DELETE FROM certificate WHERE serial_number=$1;", sn)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if _csr != nil {
		_, err = tx.Exec("DELETE FROM signing_request WHERE hash=$1;", *_csr)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	tx.Commit()
	return nil
}

// GetCertificateInformation - get certificate information
func (db PKIDBBackendPgSQL) GetCertificateInformation(cfg *PKIConfiguration, serial *big.Int) (*CertificateInformation, error) {
	var version int
	var sd *string
	var startDate time.Time
	var endDate time.Time
	var ed *string
	var subject string
	var issuer *string
	var autoRenew bool
	var autoRenewStart *int
	var autoRenewPeriod *int
	var fpMD5 *string
	var fpSHA1 *string
	var cert *string
	var csr *string
	var rd *string
	var revDate time.Time
	var revReason *int
	var keySize *int
	var sigAlgo *int
	var ext []string
	var algo string
	var state int

	sn := serial.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT version, start_date, end_date, subject, auto_renewable, auto_renew_start_period, auto_renew_validity_period, issuer, keysize, fingerprint_md5, fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, state, revocation_date, revocation_reason FROM certificate WHERE serial_number=$1;", sn).Scan(&version, &sd, &ed, &subject, &autoRenew, &autoRenewStart, &autoRenewPeriod, &issuer, &keySize, &fpMD5, &fpSHA1, &cert, &sigAlgo, pq.Array(&ext), &csr, &state, &rd, &revReason)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return nil, fmt.Errorf("%s: Certificate not found in database", GetFrame())
		}

		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	tx.Commit()

	if sigAlgo != nil {
		algo, err = db.GetSignatureAlgorithmName(cfg, *sigAlgo)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	_state, found := PKIReversStatusMap[state]
	if !found {
		return nil, fmt.Errorf("%s: Invalid state value %d", GetFrame(), state)
	}

	result := &CertificateInformation{
		SerialNumber:       serial,
		Version:            version,
		Subject:            subject,
		SignatureAlgorithm: algo,
		State:              _state,
	}

	if cert != nil {
		result.PublicKey = *cert
	}

	if sd != nil {
		startDate, err = time.Parse(PgSQLTimeFormat, *sd)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		result.NotBefore = &startDate
	}

	if ed != nil {
		endDate, err = time.Parse(PgSQLTimeFormat, *ed)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		result.NotAfter = &endDate
	}

	if keySize != nil {
		result.KeySize = *keySize
	}

	if issuer != nil {
		result.Issuer = *issuer
	}

	if fpMD5 != nil {
		result.FingerPrintMD5 = *fpMD5
	}

	if fpSHA1 != nil {
		result.FingerPrintSHA1 = *fpSHA1
	}

	if csr != nil {
		_csr, err := db.GetCertificateSigningRequest(cfg, *csr)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		result.CSR = _csr
	}

	if autoRenew {
		ar := &AutoRenew{}
		if autoRenewStart != nil {
			ar.AutoRenewStartPeriod = *autoRenewStart
		} else {
			ar.AutoRenewStartPeriod = cfg.Global.AutoRenewStartPeriod * 86400
		}
		if autoRenewPeriod != nil {
			ar.ValidityPeriod = *autoRenewPeriod
		} else {
			ar.ValidityPeriod = cfg.Global.ValidityPeriod * 86400
		}
		result.AutoRenewable = ar
	}

	if ext != nil {
		result.Extensions = make([]X509ExtensionData, 0)
		for _, e := range ext {
			_ext, err := db.GetX509Extension(cfg, e)
			if err != nil {
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			result.Extensions = append(result.Extensions, _ext)
		}
	}

	if rd != nil {
		revDate, err = time.Parse(PgSQLTimeFormat, *rd)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		rr := &RevokeRequest{
			Time: revDate,
		}
		if revReason != nil {
			rev, found := RevocationReasonReverseMap[*revReason]
			if !found {
				return nil, fmt.Errorf("%s: Invalid revocation reason code %d", GetFrame(), *revReason)
			}
			rr.Reason = rev
		} else {
			// should NEVER happen!
			rr.Reason = "unspecified"
		}
		result.Revoked = rr
	}

	return result, nil
}

// GetX509Extension - get X509 extension from database
func (db PKIDBBackendPgSQL) GetX509Extension(cfg *PKIConfiguration, id string) (X509ExtensionData, error) {
	var ext X509ExtensionData
	var name string
	var crit bool
	var data string

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return ext, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT name, critical, data FROM extension WHERE hash=$1;", id).Scan(&name, &crit, &data)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return ext, fmt.Errorf("%s: X509 extension with id %s not found in database", GetFrame(), id)
		}
		tx.Rollback()
		return ext, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	tx.Commit()

	ext.Name = name
	ext.Critical = crit
	ext.Data, err = base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ext, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	return ext, nil
}

// GetCertificateSigningRequest - get CSR from hash
func (db PKIDBBackendPgSQL) GetCertificateSigningRequest(cfg *PKIConfiguration, hash string) (string, error) {
	var csr string

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return csr, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT request FROM signing_request WHERE hash=$1;", hash).Scan(&csr)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return csr, fmt.Errorf("%s: No certificate signing request with id %s found", GetFrame(), hash)
		}
		tx.Rollback()
		return csr, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return csr, nil
}

// GetSignatureAlgorithmName - get name of signature algorithm for id
func (db PKIDBBackendPgSQL) GetSignatureAlgorithmName(cfg *PKIConfiguration, id int) (string, error) {
	var algoName string

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return "", fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT algorithm FROM signature_algorithm WHERE id=$1;", id).Scan(&algoName)
	if err != nil {
		tx.Rollback()
		return "", fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return algoName, nil
}

// SearchSubject - search subject
func (db PKIDBBackendPgSQL) SearchSubject(cfg *PKIConfiguration, search string) (*big.Int, error) {
	var sn string

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT serial_number FROM certificate WHERE subject ILIKE $1;", strings.ToLower(search)).Scan(&sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Commit()
			return nil, nil
		}
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	tx.Commit()

	serial := big.NewInt(0)
	serial, ok := serial.SetString(sn, 10)
	if !ok {
		return nil, fmt.Errorf("%s: Can't convert serial number %s to big integer", GetFrame(), sn)
	}

	return serial, nil
}

// RestoreFromJSON - Restore from JSON
func (db PKIDBBackendPgSQL) RestoreFromJSON(cfg *PKIConfiguration, j *JSONInOutput) error {
	// var ext string
	var extptr []string
	var sdate time.Time
	var ptrsdate *time.Time
	var edate time.Time
	var ptredate *time.Time
	var rdate time.Time
	var ptrrdate *time.Time

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Insert certificates
	for _, cert := range j.Certificates {
		if len(cert.Extension) == 0 {
			extptr = nil
		} else {
			extptr = cert.Extension
			/*
				ext = strings.Join(cert.Extension, ",")
				extptr = &ext
			*/
		}

		// if defined convert UTC timestamp to correct time.Time
		if cert.StartDate != nil {
			sdate = time.Unix(0, 1e+09**cert.StartDate)
			ptrsdate = &sdate
		} else {
			ptrsdate = nil
		}

		if cert.EndDate != nil {
			edate = time.Unix(0, 1e+09**cert.EndDate)
			ptredate = &edate
		} else {
			ptredate = nil
		}

		if cert.RevocationDate != nil {
			rdate = time.Unix(0, int64(1e+09**cert.RevocationDate))
			ptrrdate = &rdate
		} else {
			ptrrdate = nil
		}

		_, err := tx.Exec("INSERT INTO certificate (serial_number, version, start_date, end_date, subject, auto_renewable, auto_renew_start_period, auto_renew_validity_period, issuer, keysize, fingerprint_md5, fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, state, revocation_date, revocation_reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19);", cert.SerialNumber, cert.Version, ptrsdate, ptredate, cert.Subject, cert.AutoRenewable, cert.AutoRenewStartPeriod, cert.AutoRenewValidityPeriod, cert.Issuer, cert.KeySize, cert.FingerPrintMD5, cert.FingerPrintSHA1, cert.Certificate, cert.SignatureAlgorithmID, pq.Array(&extptr), cert.SigningRequest, cert.State, ptrrdate, cert.RevocationReason)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	// Insert CSR
	for _, csr := range j.SigningRequests {
		_, err := tx.Exec("INSERT INTO signing_request (hash, request) VALUES ($1, $2);", csr.Hash, csr.Request)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	// Insert extensions
	for _, ext := range j.Extensions {
		_, err = tx.Exec("INSERT INTO extension (hash, name, critical, data) VALUES ($1, $2, $3, $4);", ext.Hash, ext.Name, ext.Critical, ext.Data)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	// Insert signature algorithms
	for _, sig := range j.SignatureAlgorithms {
		_, err = tx.Exec("INSERT INTO signature_algorithm (id, algorithm) VALUES ($1, $2);", sig.ID, sig.Algorithm)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	tx.Commit()
	return nil
}

// BackupToJSON - backup database content to JSON
func (db PKIDBBackendPgSQL) BackupToJSON(cfg *PKIConfiguration) (*JSONInOutput, error) {
	var dump JSONInOutput
	var extptr *string
	var sdateptr *string
	var edateptr *string
	var rdateptr *string

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Certificates
	crows, err := tx.Query("SELECT serial_number, version, start_date, end_date, subject, auto_renewable, auto_renew_start_period, auto_renew_validity_period, issuer, keysize, fingerprint_md5, fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, state, revocation_date, revocation_reason FROM certificate;")
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer crows.Close()

	for crows.Next() {
		jcert := JSONCertificate{}
		err = crows.Scan(&jcert.SerialNumber, &jcert.Version, &sdateptr, &edateptr, &jcert.Subject, &jcert.AutoRenewable, &jcert.AutoRenewStartPeriod, &jcert.AutoRenewValidityPeriod, &jcert.Issuer, &jcert.KeySize, &jcert.FingerPrintMD5, &jcert.FingerPrintSHA1, &jcert.Certificate, &jcert.SignatureAlgorithmID, &extptr, &jcert.SigningRequest, &jcert.State, &rdateptr, &jcert.RevocationReason)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		// convert Start/End/Revocation date from strings to timestamps
		if sdateptr != nil {
			sdate, err := time.Parse(PgSQLTimeFormat, *sdateptr)
			if err != nil {
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			startdate := sdate.Unix()
			jcert.StartDate = &startdate
		} else {
			jcert.StartDate = nil
		}

		if edateptr != nil {
			edate, err := time.Parse(PgSQLTimeFormat, *edateptr)
			if err != nil {
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			enddate := edate.Unix()
			jcert.EndDate = &enddate
		} else {
			jcert.EndDate = nil
		}

		if rdateptr != nil {
			rdate, err := time.Parse(PgSQLTimeFormat, *rdateptr)
			if err != nil {
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			revdate := float64(rdate.Unix())
			jcert.RevocationDate = &revdate
		} else {
			jcert.RevocationDate = nil
		}

		// extensions
		if extptr != nil {
			jcert.Extension = make([]string, 0)
			for _, e := range strings.Split(*extptr, ",") {
				jcert.Extension = append(jcert.Extension, e)
			}
		}

		dump.Certificates = append(dump.Certificates, jcert)
	}
	err = crows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Signing requests
	srows, err := tx.Query("SELECT hash, request FROM signing_request;")
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer srows.Close()

	for srows.Next() {
		csr := JSONSigningRequest{}
		err = srows.Scan(&csr.Hash, &csr.Request)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		dump.SigningRequests = append(dump.SigningRequests, csr)
	}
	err = srows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Extensions
	erows, err := tx.Query("SELECT hash, name, critical, data FROM extension;")
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer erows.Close()

	for erows.Next() {
		ext := JSONExtension{}
		err = erows.Scan(&ext.Hash, &ext.Name, &ext.Critical, &ext.Data)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		dump.Extensions = append(dump.Extensions, ext)

	}
	err = erows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Signature algorithms
	arows, err := tx.Query("SELECT id, algorithm FROM signature_algorithm;")
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer arows.Close()

	for arows.Next() {
		sigs := JSONSignatureAlgorithm{}
		err = arows.Scan(&sigs.ID, &sigs.Algorithm)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		dump.SignatureAlgorithms = append(dump.SignatureAlgorithms, sigs)

	}
	err = arows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return &dump, nil
}

// GetSerialNumbersByState - list serial numbers by state
func (db PKIDBBackendPgSQL) GetSerialNumbersByState(cfg *PKIConfiguration, state int) ([]*big.Int, error) {
	var results = make([]*big.Int, 0)
	var resmap = make(map[string]bool)
	var sn string

	_, found := PKIReversStatusMap[state]
	if !found && state != ListAllSerialNumbers {
		return nil, fmt.Errorf("%s: Invalid state %d", GetFrame(), state)
	}

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if state == ListAllSerialNumbers {
		all, err := tx.Query("SELECT serial_number FROM certificate;")
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		defer all.Close()

		for all.Next() {
			err = all.Scan(&sn)
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			resmap[sn] = true
		}
		err = all.Err()
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	} else {
		srows, err := tx.Query("SELECT serial_number FROM certificate WHERE state=$1;", state)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		defer srows.Close()

		for srows.Next() {
			err = srows.Scan(&sn)
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			// Note: Although there are no duplicates here (thanks to the constraints), there will be if
			//       we scan for expired/invalid based on the date (e.g. if pkidb housekeeping wasn't run yet (or at all))
			resmap[sn] = true
		}
		err = srows.Err()
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		// If housekeeping wasn't run (yet or at all), we can find invalid/expired certificates based on the start/end dates
		if state == PKICertificateStatusExpired {
			erows, err := tx.Query("SELECT serial_number FROM certificate WHERE start_date < $1 AND end_date < $1;", time.Now())
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			defer erows.Close()

			for erows.Next() {
				err = erows.Scan(&sn)
				if err != nil {
					tx.Rollback()
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}
				resmap[sn] = true
			}
			err = erows.Err()
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}

		if state == PKICertificateStatusInvalid {
			irows, err := tx.Query("SELECT serial_number FROM certificate WHERE start_date > end_date OR start_date > $1;", time.Now())
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			defer irows.Close()

			for irows.Next() {
				err = irows.Scan(&sn)
				if err != nil {
					tx.Rollback()
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}
				resmap[sn] = true
			}
			err = irows.Err()
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
	}

	tx.Commit()

	for key := range resmap {
		serial := big.NewInt(0)
		serial, ok := serial.SetString(key, 10)
		if !ok {
			return nil, fmt.Errorf("%s: Can't convert serial number %s to big integer", GetFrame(), key)
		}
		results = append(results, serial)
	}

	return results, nil
}

// LockSerialNumber - lock serial number in databse
func (db PKIDBBackendPgSQL) LockSerialNumber(cfg *PKIConfiguration, serial *big.Int, state int, force bool) error {
	var _sn string

	sn := serial.Text(10)

	_, found := PKIReversStatusMap[state]
	if !found && state != ListAllSerialNumbers {
		return fmt.Errorf("%s: Invalid state %d", GetFrame(), state)
	}

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// XXX: A much more elegant way would be INSERT INTO ... ON CONFLICT DO ...
	err = tx.QueryRow("SELECT serial_number FROM certificate WHERE serial_number=$1;", sn).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			lockMsg := fmt.Sprintf("Locked serial number %s", sn)
			_, err = tx.Exec("INSERT INTO certificate (serial_number, subject, certificate, version, state) VALUES ($1, $2, $2, $3, $4);", sn, lockMsg, 0, state)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}

			tx.Commit()
			return nil
		}
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if force {
		_, err = tx.Exec("UPDATE certificate SET state=? WHERE serial_number=$1;", state, sn)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		tx.Commit()
		return nil
	}

	return fmt.Errorf("%s: Serial number %s already present in the database", GetFrame(), sn)
}

// GetRevokedCertificates - get revoked certificates
func (db PKIDBBackendPgSQL) GetRevokedCertificates(cfg *PKIConfiguration) ([]RevokeRequest, error) {
	var result = make([]RevokeRequest, 0)
	var sn string
	var rdatestr *string
	var rdate time.Time
	var rreason int

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	srows, err := tx.Query("SELECT serial_number, revocation_date, revocation_reason FROM certificate WHERE state=$1;", PKICertificateStatusRevoked)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	for srows.Next() {
		err = srows.Scan(&sn, &rdatestr, &rreason)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		serial := big.NewInt(0)
		serial, ok := serial.SetString(sn, 10)
		if !ok {
			tx.Rollback()
			return nil, fmt.Errorf("%s: Can't convert serial number %s to big integer", GetFrame(), sn)
		}

		if rdatestr == nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: Missing revocation date in revoked certificate %s", GetFrame(), serial)
		}

		rdate, err = time.Parse(PgSQLTimeFormat, *rdatestr)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		reason, found := RevocationReasonReverseMap[rreason]
		if !found {
			tx.Rollback()
			return nil, fmt.Errorf("%s: Invalid revocation reason %d", GetFrame(), rreason)
		}

		rr := RevokeRequest{
			SerialNumber: serial,
			Time:         rdate,
			Reason:       reason,
		}

		result = append(result, rr)
	}
	err = srows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	tx.Commit()

	return result, fmt.Errorf("%s: %s", GetFrame(), err.Error())

}

// GetCertificate - get certificate as ASN1 DER data
func (db PKIDBBackendPgSQL) GetCertificate(cfg *PKIConfiguration, serial *big.Int) ([]byte, error) {
	var cert string

	sn := serial.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	err = tx.QueryRow("SELECT certificate FROM certificate WHERE serial_number=$1;", sn).Scan(&cert)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Commit()
			return nil, nil
		}
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	/*
		data, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, err
		}
	*/

	data := "-----BEGIN CERTIFICATE-----\n"
	// reformat string to public key in PEM format
	lines64Chars := len(cert) / 64
	for i := 0; i < lines64Chars; i++ {
		data += cert[64*i:64*(i+1)] + "\n"
	}
	if len(cert)%64 != 0 {
		data += cert[64*lines64Chars:len(cert)] + "\n"
	}
	data += "-----END CERTIFICATE-----"

	return []byte(data), nil
}

// StoreState - set state
func (db PKIDBBackendPgSQL) StoreState(cfg *PKIConfiguration, serial *big.Int, state string) error {
	sn := serial.Text(10)
	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	st, found := PKIStatusMap[state]
	if !found {
		tx.Rollback()
		return fmt.Errorf("%s: Invalid state %s", GetFrame(), state)
	}

	_, err = tx.Exec("UPDATE certifiate SET state=$1 WHERE serial_number=$2;", st, sn)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return nil
}

// GetStatistics - get statistics
func (db PKIDBBackendPgSQL) GetStatistics(cfg *PKIConfiguration) (map[string]map[string]int64, error) {
	var sizeStat = make(map[string]int64)
	var keySizeStat = make(map[string]int64)
	var sigAlgoStat = make(map[string]int64)
	var revokedStat = make(map[string]int64)
	var result = make(map[string]map[string]int64)
	var key string
	var nkey int
	var value int64

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// states
	srows, err := tx.Query("SELECT state, COUNT(state) FROM certificate GROUP BY state;")
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer srows.Close()

	for srows.Next() {
		err = srows.Scan(&nkey, &value)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		key, found := PKIReversStatusMap[nkey]
		if !found {
			tx.Rollback()
			return nil, fmt.Errorf("%s: Invalid state %d", GetFrame(), nkey)
		}
		sizeStat[key] = value
	}
	err = srows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// key size
	krows, err := tx.Query("SELECT keysize, COUNT(keysize) FROM certificate WHERE state=$1 GROUP BY keysize;", PKICertificateStatusValid)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer krows.Close()

	for krows.Next() {
		err = krows.Scan(&key, &value)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		keySizeStat[key] = value
	}
	err = krows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// algorithms
	arows, err := tx.Query("SELECT algorithm, COUNT(algorithm) FROM signature_algorithm INNER JOIN certificate ON certificate.signature_algorithm_id=signature_algorithm.id WHERE certificate.state=$1 GROUP BY algorithm;", PKICertificateStatusValid)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer arows.Close()

	for arows.Next() {
		err = arows.Scan(&key, &value)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		sigAlgoStat[key] = value
	}
	err = arows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// revoked
	rrows, err := tx.Query("SELECT revocation_reason, COUNT(revocation_reason) FROM certificate WHERE state=$1 GROUP BY revocation_reason;", PKICertificateStatusRevoked)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer rrows.Close()

	for rrows.Next() {
		err = rrows.Scan(&nkey, &value)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		key, found := RevocationReasonReverseMap[nkey]
		if !found {
			tx.Rollback()
			return nil, fmt.Errorf("%s: Invalid revocation reason %d", GetFrame(), nkey)
		}
		revokedStat[key] = value
	}
	err = rrows.Err()
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()

	result["state"] = sizeStat
	result["keysize"] = keySizeStat
	result["signature_algorithm"] = sigAlgoStat
	result["revoked"] = revokedStat

	return result, nil
}

// DeleteAutoRenew - delete auto renew data
func (db PKIDBBackendPgSQL) DeleteAutoRenew(cfg *PKIConfiguration, serial *big.Int) error {
	sn := serial.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	_, err = tx.Exec("UPDATE certificate SET auto_renewable=False, auto_renew_start_period=NULL, auto_renew_validity_period=NULL WHERE serial_number=$1;", sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return fmt.Errorf("%s: Can't find serial number %s in database", GetFrame(), sn)
		}
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return nil
}

// Housekeeping - housekeeping
func (db PKIDBBackendPgSQL) Housekeeping(cfg *PKIConfiguration, autoRenew bool, period int) error {
	var sn string
	var dstr string
	var startPeriod int64
	var validPeriod int64
	var serial *big.Int
	var newEnd time.Time
	var oldCSR *x509.CertificateRequest

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if autoRenew {
		arows, err := tx.Query("SELECT serial_number, end_date, auto_renew_start_period, auto_renew_validity_period FROM certificate WHERE auto_renewable=True AND (state=$1 OR state=$2);", PKICertificateStatusValid, PKICertificateStatusExpired)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		defer arows.Close()
		for arows.Next() {
			err = arows.Scan(&sn, &dstr, &startPeriod, &validPeriod)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		}
		err = arows.Err()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		edate, err := time.Parse(PgSQLTimeFormat, dstr)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		delta := time.Now().Sub(edate).Seconds()
		if int64(delta) >= startPeriod {
			serial = big.NewInt(0)
			serial, ok := serial.SetString(sn, 10)
			if !ok {
				tx.Rollback()
				return fmt.Errorf("%s: Can't convert serial number %s to big integer", GetFrame(), sn)
			}

			certinfo, err := db.GetCertificateInformation(cfg, serial)
			if err != nil {
				tx.Rollback()
				return err
			}

			if period != 0 {
				newEnd = time.Now().Add(time.Duration(24) * time.Hour * time.Duration(period))
			} else {
				newEnd = time.Now().Add(time.Duration(24) * time.Hour * time.Duration(cfg.Global.ValidityPeriod))
			}

			raw, err := RenewCertificate(cfg, serial, newEnd)
			if err != nil {
				tx.Rollback()
				return err
			}

			ncert, err := x509.ParseCertificate(raw)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}

			if certinfo.CSR != "" {
				rawCSR, err := base64.StdEncoding.DecodeString(certinfo.CSR)
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}
				oldCSR, err = x509.ParseCertificateRequest(rawCSR)
				if err != nil {
					tx.Rollback()
					return fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}
			} else {
				oldCSR = nil
			}

			// create import struct
			imp := &ImportCertificate{
				Certificate: ncert,
				AutoRenew:   certinfo.AutoRenewable,
				Revoked:     certinfo.Revoked,
				CSR:         oldCSR,
			}
			err = db.StoreCertificate(cfg, imp, true)
			if err != nil {
				tx.Rollback()
				return err
			}

			if certinfo.State == "expired" {
				err = db.StoreState(cfg, serial, "valid")
				if err != nil {
					tx.Rollback()
					return err
				}
			}
		}
	}

	// Set all invalid certificates to valid if notBefore < now and notAfter > now
	_, err = tx.Exec("UPDATE certificate SET state=$1 WHERE state=$2 AND (start_date < $3) AND (end_date > $3);", PKICertificateStatusValid, PKICertificateStatusInvalid, time.Now())
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Set all valid certificates to invalid if notBefore >= now
	_, err = tx.Exec("UPDATE certificate SET state=$1 WHERE state=$2 AND (start_date > $3);", PKICertificateStatusInvalid, PKICertificateStatusValid, time.Now())
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	// Set all valid certificates to expired if notAfter <= now
	_, err = tx.Exec("UPDATE certificate SET state=$1 WHERE state=$2 AND (end_date <= $3)", PKICertificateStatusExpired, PKICertificateStatusValid, time.Now())
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	tx.Commit()
	return nil
}
