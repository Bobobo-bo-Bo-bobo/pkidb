package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"math/big"
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
func (db PKIDBBackendSQLite3) StoreCertificateSigningRequest(cfg *PKIConfiguration, csr *x509.CertificateRequest) error {
	var _hash string

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
			tx.Commit()
			return nil
		}
		tx.Rollback()
		return err
	}

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

	tx.Commit()
	return nil
}

// StoreCertificate - Store certificate in database
func (db PKIDBBackendSQLite3) StoreCertificate(cfg *PKIConfiguration, cert *ImportCertificate, replace bool) error {
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

	if already && !replace {
		return fmt.Errorf("A certificate with this serial number already exist in the database")
	}

	if cert.Revoked {
		state = PKICertificateStatusRevoked
	}

	algoid, err := db.StoreSignatureAlgorithm(cfg, cert.Certificate.SignatureAlgorithm)
	if err != nil {
		return err
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

	if cert.CSR != nil {
		err = db.StoreCertificateSigningRequest(cfg, cert.CSR)
		if err != nil {
			tx.Rollback()
			return err
		}
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
