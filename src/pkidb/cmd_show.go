package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

// CmdShow - show certificate
func CmdShow(cfg *PKIConfiguration, args []string) error {
	var snList = make([]string, 0)
	var splitted []string
	var serial *big.Int
	var out string
	var fd *os.File
	var err error

	argParse := flag.NewFlagSet("cmd-import", flag.ExitOnError)
	var output = argParse.String("output", "", "Write certificate information to <output> instead of standard output")
	argParse.Parse(args)

	cmdShowTrailing := argParse.Args()
	if len(cmdShowTrailing) == 0 {
		raw, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		rawstr := string(raw)
		rawstr = strings.Replace(rawstr, "\r", "", -1)
		rawstr = strings.Replace(rawstr, "\n", " ", -1)
		rawstr = strings.Replace(rawstr, "\t", " ", -1)

		splitted = strings.Split(rawstr, " ")
	} else {
		splitted = cmdShowTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			snList = append(snList, strings.TrimSpace(v))
		}
	}

	for i, sn := range snList {
		serial = big.NewInt(0)
		serial, ok := serial.SetString(sn, 0)
		if !ok {
			return fmt.Errorf("Invalid serial number %s", sn)
		}

		ci, err := cfg.DBBackend.CertificateInformation(cfg, serial)
		if err != nil {
			return err
		}

		out += PrintCertificateInformation(ci)
		if err != nil {
			return err
		}

		if i < len(snList)-1 {
			out += "\n"
		}
	}

	if *output == "" {
		fd = os.Stdout
	} else {
		fd, err = os.Create(*output)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprintf(fd, "%s", out)
	if err != nil {
		return err
	}
	if *output != "" {
		err = fd.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// PrintCertificateInformation - print certificate information
func PrintCertificateInformation(ci *CertificateInformation) string {
	out := fmt.Sprintf("Serial number: %s (0x%s)\n", ci.SerialNumber.Text(10), ci.SerialNumber.Text(16))
	out += fmt.Sprintf("SSL Version: %d\n", ci.Version)
	out += fmt.Sprintf("Key size: %d\n", ci.KeySize)

	if ci.SignatureAlgorithm == "" {
		out += fmt.Sprintf("Signature algorithm: -\n")
	} else {
		out += fmt.Sprintf("Signature algorithm: %s\n", ci.SignatureAlgorithm)
	}

	out += fmt.Sprintf("State: %s\n", ci.State)

	if ci.Revoked != nil {
		out += fmt.Sprintf(" * Revoked on: %s\n", ci.Revoked.Time.Format(OutputTimeFormat))
		out += fmt.Sprintf(" * Revocation reason: %s\n", ci.Revoked.Reason)
	}

	if ci.NotBefore != nil {
		out += fmt.Sprintf("Begins on: %s\n", ci.NotBefore.Format(OutputTimeFormat))
	} else {

		out += fmt.Sprintf("Begins on: -\n")
	}

	if ci.NotAfter != nil {
		out += fmt.Sprintf("Ends on: %s\n", ci.NotAfter.Format(OutputTimeFormat))
	} else {

		out += fmt.Sprintf("Ends on: -\n")
	}

	out += fmt.Sprintf("Subject: %s\n", ci.Subject)

	if ci.Issuer == "" {
		out += fmt.Sprintf("Issuer: -\n")
	} else {
		out += fmt.Sprintf("Issuer: %s\n", ci.Issuer)
	}

	if ci.FingerPrintMD5 == "" {
		out += fmt.Sprintf("Fingerprint (MD5): -\n")
	} else {
		out += fmt.Sprintf("Fingerprint (MD5): %s\n", ci.FingerPrintMD5)
	}

	if ci.FingerPrintSHA1 == "" {
		out += fmt.Sprintf("Fingerprint (SHA1): -\n")
	} else {
		out += fmt.Sprintf("Fingerprint (SHA1): %s\n", ci.FingerPrintSHA1)
	}

	if ci.AutoRenewable != nil {
		out += fmt.Sprintf("Auto renewable: True\n")
		out += fmt.Sprintf(" * Auto renew starts before expiration: %s\n", PrintInterval(float64(ci.AutoRenewable.Delta)))
		out += fmt.Sprintf(" * Auto renew for: %s\n", PrintInterval(float64(ci.AutoRenewable.Period)))
	} else {
		out += fmt.Sprintf("Auto renewable: False\n")
	}

	out += fmt.Sprintf("Extensions: %d\n", len(ci.Extensions))

	for i, ext := range ci.Extensions {
		out += fmt.Sprintf(" * Extension: %d\n", i)
		out += fmt.Sprintf("  * Name: %s\n", ext.Name)
		out += fmt.Sprintf("  * Critical: %s\n", BoolToPythonString(ext.Critical))
		out += fmt.Sprintf("  * Data: %s\n", base64.StdEncoding.EncodeToString(ext.Data))
	}

	if ci.PublicKey != "" {
		out += fmt.Sprintf("Public key: %s\n", ci.PublicKey)
	} else {
		out += fmt.Sprintf("Public key: None\n")
	}

	if ci.CSR != "" {
		out += fmt.Sprintf("Certificate signing request: %s\n", ci.CSR)
	} else {
		out += fmt.Sprintf("Certificate signing request: None\n")
	}

	return out
}
