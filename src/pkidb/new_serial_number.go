package main

import (
	"crypto/rand"
	"math/big"
)

// NewSerialNumber - Generate a new serial number
func NewSerialNumber(cfg *PKIConfiguration) (*big.Int, error) {
	var serial *big.Int
	var err error

	if cfg.Global.SerialNumber == "random" {
		serial, err = rand.Int(rand.Reader, MaximumSerialNumber)
		if err != nil {
			return nil, err
		}

		// Increment result by one because RFC 3280 defines the serial number
		// as a positive integer ("The serial number MUST be a positive integer ...").
		// Although "0" also classify as "positive integer" it isn't valid as serial
		// number. rand.Int returns a value in in [0, MaximumSerialNumber) which may be 0 (although unlikely)
		serial = serial.Add(serial, big.NewInt(1))
	}
    // TODO: Handle incremental serial numbers. This requires database activity ...
	return serial, nil
}
