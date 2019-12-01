package main

import (
	"math/big"
)

// PKIDBBackend - Database backend
type PKIDBBackend interface {
	GetLastSerialNumber(*DatabaseConfiguration) (*big.Int, error)
}
