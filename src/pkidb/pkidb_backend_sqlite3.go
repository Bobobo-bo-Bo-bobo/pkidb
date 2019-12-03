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
	_ "github.com/mattn/go-sqlite3"
	"math/big"
	"strings"
)

// PKIDBBackendSQLite3 - SQLite3 database
type PKIDBBackendSQLite3 struct {
	Database string
}

// Initialise - Initialise SQLite3 database connection
func (db PKIDBBackendSQLite3) Initialise(cfg *PKIConfiguration) error {
	var one int

	db.Database = cfg.Database.Database

	_db, err := db.OpenDatabase(cfg)
	if err != nil {
		return err
	}

	err = _db.QueryRow("SELECT 1=1").Scan(&one)
	if err != nil {
		return err
	}

	// Should NEVER happen ;)
	if one != 1 {
		return fmt.Errorf("Unexpected result from 'SELECT 1=1;'")
	}

	cfg.Database.dbhandle = _db
	return nil
}

// GetLastSerialNumber - get last serial number from database
func (db PKIDBBackendSQLite3) GetLastSerialNumber(cfg *PKIConfiguration) (*big.Int, error) {
	var snString string
	var sn *big.Int

	if cfg.Database.dbhandle == nil {
		return nil, fmt.Errorf("Database handle is not initialised")
	}

	err := cfg.Database.dbhandle.QueryRow("SELECT MAX(serial_number) FROM certificate").Scan(&snString)
	if err != nil {
		return nil, fmt.Errorf("No serial number found in database")
	}

	sn = big.NewInt(-1)
	sn, ok := sn.SetString(snString, 0)
	if !ok {
		return nil, fmt.Errorf("Can't convert serial number")
	}

	return sn, nil
}

// IsFreeSerialNumber - check if serial number is not used
func (db PKIDBBackendSQLite3) IsFreeSerialNumber(cfg *PKIConfiguration, serial *big.Int) (bool, error) {
	var _sn string

	sn := serial.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return false, err
	}

	query, err := tx.Prepare("SELECT serial_number FROM certificate WHERE serial_number=?;")
	if err != nil {
		tx.Rollback()
		return false, err
	}
	defer query.Close()

	err = query.QueryRow(sn).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Commit()
			return true, nil
		}
		tx.Rollback()
		return false, err
	}

	return false, nil
}

// IsUsedSerialNumber - check if serial number is already used
func (db PKIDBBackendSQLite3) IsUsedSerialNumber(cfg *PKIConfiguration, serial *big.Int) (bool, error) {
	free, err := db.IsFreeSerialNumber(cfg, serial)
	return !free, err
}

// OpenDatabase - Open database connection
func (db PKIDBBackendSQLite3) OpenDatabase(cfg *PKIConfiguration) (*sql.DB, error) {
	dbhandle, err := sql.Open("sqlite3", cfg.Database.Database)
	if err != nil {
		return nil, err
	}

	return dbhandle, nil
}

// CloseDatabase - close database connection
func (db PKIDBBackendSQLite3) CloseDatabase(h *sql.DB) error {
	var err error

	if h != nil {
		err = h.Close()
	}

	return err
}

// StoreCertificateSigningRequest - store CSR
func (db PKIDBBackendSQLite3) StoreCertificateSigningRequest(cfg *PKIConfiguration, ci *ImportCertificate) error {
	var _hash string

	sn := ci.Certificate.SerialNumber.Text(10)
	csr := ci.CSR

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return err
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(csr.Raw))

	fetch, err := tx.Prepare("SELECT hash FROM signing_request WHERE hash=?")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer fetch.Close()

	err = fetch.QueryRow(_hash).Scan(&_hash)
	if err != nil {
		if err == sql.ErrNoRows {
			insert, err := tx.Prepare("INSERT INTO signing_request (hash, request) VALUES (?, ?);")
			if err != nil {
				tx.Rollback()
				return err
			}
			defer insert.Close()

			_, err = insert.Exec(hash, base64.StdEncoding.EncodeToString(csr.Raw))
			if err != nil {
				tx.Rollback()
				return err
			}

			upd, err := tx.Prepare("UPDATE certificate SET signing_request=? WHERE serial_number=?;")
			if err != nil {
				tx.Rollback()
				return err
			}
			defer upd.Close()

			_, err = upd.Exec(hash, sn)
			if err != nil {
				tx.Rollback()
				return err
			}

			tx.Commit()
			return nil
		}
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

// StoreCertificate - Store certificate in database
func (db PKIDBBackendSQLite3) StoreCertificate(cfg *PKIConfiguration, cert *ImportCertificate, replace bool) error {
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
		return err
	}

	if cert.IsDummy {
		state = PKICertificateStatusDummy
	}

	if already && !replace {
		return fmt.Errorf("A certificate with this serial number already exist in the database")
	}

	if cert.Revoked != nil {
		state = PKICertificateStatusRevoked
	}

	if !cert.IsDummy {
		algoid, err = db.StoreSignatureAlgorithm(cfg, cert.Certificate.SignatureAlgorithm)
		if err != nil {
			return err
		}
	}

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return err
	}

	if already && replace {
		del, err := tx.Prepare("DELETE FROM certificate WHERE serial_number=?;")
		if err != nil {
			tx.Rollback()
			return err
		}
		_, err = del.Exec(sn)
		if err != nil {
			tx.Rollback()
			return err
		}
		del.Close()
	}

	if cert.IsDummy {
		ins, err := tx.Prepare("INSERT INTO certificate (serial_number, version, state, subject) VALUES (?, ?, ?, ?);")
		if err != nil {
			tx.Rollback()
			return err
		}
		defer ins.Close()

		_, err = ins.Exec(sn, 3, state, DummyCertificateSubject)
		if err != nil {
			tx.Rollback()
			return err
		}
		tx.Commit()
		return nil
	}

	statement, err := tx.Prepare("INSERT INTO certificate (serial_number, version, start_date, end_date, subject, fingerprint_md5, fingerprint_sha1, certificate, state, issuer, signature_algorithm_id, keysize) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer statement.Close()

	_, err = statement.Exec(sn, version, start, end, subject, _md5, _sha1, rawCert, state, issuer, algoid, length)
	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()

	if cert.CSR != nil {
		err = db.StoreCertificateSigningRequest(cfg, cert)
		if err != nil {
			return err
		}
	}

	if cert.Certificate.Extensions != nil {
		err = db.StoreX509Extension(cfg, cert, cert.Certificate.Extensions)
		if err != nil {
			return err
		}
	}

	if cert.Certificate.ExtraExtensions != nil {
		err = db.StoreX509Extension(cfg, cert, cert.Certificate.ExtraExtensions)
		if err != nil {
			return err
		}
	}

	if cert.Revoked != nil {
		err = db.StoreRevocation(cfg, cert.Revoked)
		if err != nil {
			return err
		}
	}

	if cert.AutoRenew != nil {
		err = db.StoreAutoRenew(cfg, cert.AutoRenew)
		if err != nil {
			return err
		}
	}

	return nil
}

// StoreAutoRenew - store auto-renew options
func (db PKIDBBackendSQLite3) StoreAutoRenew(cfg *PKIConfiguration, auto *AutoRenew) error {
	var _sn string

	sn := auto.SerialNumber.Text(10)

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return err
	}

	query, err := tx.Prepare("SELECT serial_number FROM certificate WHERE serial_number=?;")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer query.Close()

	err = query.QueryRow(sn).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return fmt.Errorf("Certificate not found in database")
		}
		tx.Rollback()
		return err
	}

	upd, err := tx.Prepare("UPDATE certificate SET auto_renewable=?, auto_renew_start_period=?, auto_renew_validity_period=? WHERE serial_number=?;")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer upd.Close()

	_, err = upd.Exec(true, auto.Period, auto.Delta, sn)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

// StoreSignatureAlgorithm - store x509.SignatureAlgorithm name in database
func (db PKIDBBackendSQLite3) StoreSignatureAlgorithm(cfg *PKIConfiguration, algo x509.SignatureAlgorithm) (int, error) {
	name, found := SignatureAlgorithmNameMap[algo]
	if !found {
		return -1, fmt.Errorf("Can't map x509.SignatureAlgorithm to a name")
	}

	return db.StoreSignatureAlgorithmName(cfg, name)
}

// StoreSignatureAlgorithmName - insert x509.SignatureAlgorithm name
func (db PKIDBBackendSQLite3) StoreSignatureAlgorithmName(cfg *PKIConfiguration, name string) (int, error) {
	var algoid int

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return -1, err
	}

	statement, err := tx.Prepare("SELECT id FROM signature_algorithm WHERE algorithm=?;")
	if err != nil {
		tx.Rollback()
		return -1, err
	}
	defer statement.Close()

	err = statement.QueryRow(name).Scan(&algoid)
	if err != nil {
		if err == sql.ErrNoRows {
			ins, err := tx.Prepare("INSERT INTO signature_algorithm (algorithm) VALUES (?);")
			if err != nil {
				tx.Rollback()
				return -1, err
			}

			_, err = ins.Exec(name)
			get, err := tx.Prepare("SELECT id FROM signature_algorithm WHERE algorithm=?;")
			if err != nil {
				tx.Rollback()
				return -1, err
			}

			err = get.QueryRow(name).Scan(&algoid)
			if err != nil {
				tx.Rollback()
				return -1, err
			}

			tx.Commit()
			return algoid, nil
		}
		tx.Rollback()
		return -1, err
	}
	tx.Commit()

	return algoid, nil
}

// SerialNumberAlreadyPresent - check if serial number is already present in the database
func (db PKIDBBackendSQLite3) SerialNumberAlreadyPresent(cfg *PKIConfiguration, sn *big.Int) (bool, error) {
	var _sn string

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return false, err
	}

	fetch, err := tx.Prepare("SELECT serial_number FROM certificate WHERE serial_number=?;")
	if err != nil {
		tx.Rollback()
		return false, err
	}
	defer fetch.Close()

	err = fetch.QueryRow(sn.Text(10)).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			tx.Commit()
			return false, nil
		}
		tx.Rollback()
		return false, err
	}

	tx.Commit()
	return true, nil
}

// StoreX509Extension - store x509.Extension in database
func (db PKIDBBackendSQLite3) StoreX509Extension(cfg *PKIConfiguration, cert *ImportCertificate, extensions []pkix.Extension) error {
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
		return err
	}
	check, err := tx.Prepare("SELECT hash FROM extension WHERE hash=?;")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer check.Close()

	ins, err := tx.Prepare("INSERT INTO extension (hash, name, critical, data) VALUES (?, ?, ?, ?);")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer ins.Close()

	for _, ext := range extensions {
		name, found = OIDMap[ext.Id.String()]
		if !found {
			name = ext.Id.String()
		}
		data = base64.StdEncoding.EncodeToString(ext.Value)

		// primary key is the sha512 hash of name+critical+Base64(data)
		pkey = fmt.Sprintf("%x", sha512.Sum512([]byte(name+BoolToPythonString(ext.Critical)+data)))
		err = check.QueryRow(pkey).Scan(&_hash)
		if err != nil {
			if err == sql.ErrNoRows {
				_, err = ins.Exec(pkey, name, ext.Critical, data)
				if err != nil {
					tx.Rollback()
					return err
				}
				ids[pkey] = true
			} else {
				tx.Rollback()
				return err
			}
		}
		ids[pkey] = true
	}

	for key := range ids {
		idList = append(idList, key)
	}

	upd, err := tx.Prepare("UPDATE certificate SET extension=? WHERE serial_number=?;")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer upd.Close()

	_, err = upd.Exec(strings.Join(idList, ","), sn)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

// StoreRevocation - store certificate revocation
func (db PKIDBBackendSQLite3) StoreRevocation(cfg *PKIConfiguration, rev *RevokeRequest) error {
	var _sn string

	sn := rev.SerialNumber.Text(10)

	reason, found := RevocationReasonMap[strings.ToLower(rev.Reason)]
	if !found {
		return fmt.Errorf("Unknown revocation reason")
	}

	tx, err := cfg.Database.dbhandle.Begin()
	if err != nil {
		return err
	}

	query, err := tx.Prepare("SELECT serial_number FROM certificate WHERE serial_number=?;")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer query.Close()

	err = query.QueryRow(sn).Scan(&_sn)
	if err != nil {
		if err == sql.ErrNoRows {
			if rev.Force {
				// close current transaction to avoid locking issues when calling StoreCertificate
				tx.Commit()

				dummyCert := &x509.Certificate{
					SerialNumber: rev.SerialNumber,
				}
				ic := &ImportCertificate{
					Certificate: dummyCert,
					IsDummy:     true,
				}
				err = db.StoreCertificate(cfg, ic, false)
				if err != nil {
					tx.Rollback()
					return err
				}
			} else {
				tx.Rollback()
				return fmt.Errorf("Certificate not found in database")
			}
		} else {
			tx.Rollback()
			return err
		}
	}
	tx.Commit()

	// create a new transaction
	tx, err = cfg.Database.dbhandle.Begin()
	if err != nil {
		return err
	}
	ins, err := tx.Prepare("UPDATE certificate SET revocation_reason=?, revocation_date=?, state=? WHERE serial_number=?;")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer ins.Close()

	_, err = ins.Exec(reason, rev.Time, PKICertificateStatusRevoked, sn)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}
