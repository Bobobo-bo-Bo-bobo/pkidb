package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

// CmdSign - Command "sign"
func CmdSign(cfg *PKIConfiguration, args []string) error {
	var sr SignRequest
	var validityPeriod int
	var csrData []byte
	var err error

	argParse := flag.NewFlagSet("cmd-sign", flag.ExitOnError)

	var extensions = flag.String("extension", "", "X509 extension. Can be repeated for multiple extensions")
	var extendedKeyUsage = flag.String("extended-keyusage", "", "Comma separated list of extended key usage bits")
	var san = flag.String("san", "", "subjectAltName extension")
	var autoRenew = flag.Bool("auto-renew", false, "Mark certificate as auto renewable")
	var basicConstraint = flag.String("basic-constraint", "", "Set basic constraints prefix critical")
	var keyUsage = flag.String("keyusage", "", "Comma separated list of keyUsage bits")
	var noRegister = flag.Bool("no-register", false, "Don't store certificate data - except the serial number - in the database")
	var output = flag.String("output", "", "Write data to <outfile> instead of stdout")
	var startIn = flag.Int("start-in", 0, "Validity of the new certificate starts in startin days")
	var template = flag.String("template", "", "Use a template file for certificate signing")
	var validFor = flag.Int("valid-for", 0, "ew certificate will be valid for validfor days")

	argParse.Parse(args)

	cmdSignTrailing := argParse.Args()
	if len(cmdSignTrailing) > 1 {
		return fmt.Errorf("Too many arguments")
	}

	if len(cmdSignTrailing) == 0 {
		csrData, err = ioutil.ReadAll(os.Stdin)
	} else {
		csrData, err = ioutil.ReadFile(cmdSignTrailing[0])
	}
	if err != nil {
		return err
	}
	sr.CSRData = csrData

	if *extensions != "" {
		sr.Extension = make([]X509ExtensionData, 0)
		for _, ext := range strings.Split(*extensions, ",") {
			e := X509ExtensionData{}

			rawExt := strings.Split(ext, ":")
			if len(rawExt) != 5 {
				return fmt.Errorf("Invalid extension data")
			}

			e.Name = rawExt[0]

			if rawExt[1] == "" || rawExt[1] == "0" {
				e.Critical = false
			} else if rawExt[1] == "1" {
				e.Critical = true
			} else {
				return fmt.Errorf("Invalid extension data")
			}

			e.Subject = rawExt[2]
			e.Issuer = rawExt[3]

			if rawExt[4] != "" {
				e.Data, err = base64.StdEncoding.DecodeString(rawExt[4])
				if err != nil {
					return err
				}
			}
			sr.Extension = append(sr.Extension, e)
		}
	}

	if *extendedKeyUsage != "" {
		sr.ExtendedKeyUsage = make([]X509ExtendedKeyUsageData, 0)
		for _, eku := range strings.Split(*extendedKeyUsage, ",") {
			ekud := X509ExtendedKeyUsageData{}
			rawEku := strings.Split(eku, ":")

			if len(rawEku) == 1 {
				ekud.Critical = false
				ekud.Flags = rawEku[0]
			} else if len(rawEku) == 2 {
				ekud.Critical = true
				ekud.Flags = rawEku[1]
			} else {
				return fmt.Errorf("Invalid extended key usage data")
			}

			sr.ExtendedKeyUsage = append(sr.ExtendedKeyUsage, ekud)
		}
	}

	if *san != "" {
		sr.SAN = make([]X509SubjectAlternateNameData, 0)
		for _, san := range strings.Split(*san, ",") {
			_san := X509SubjectAlternateNameData{}
			rawSan := strings.Split(san, ":")
			if len(rawSan) == 2 {
				_san.Type = rawSan[0]
				_san.Value = rawSan[1]
			} else if len(rawSan) == 3 {
				if rawSan[0] == "" || rawSan[1] == "0" {
					_san.Critical = false
				} else if rawSan[0] == "1" {
					_san.Critical = true
				} else {
					return fmt.Errorf("Invalind subject alternate name")
				}
				_san.Type = rawSan[0]
				_san.Value = rawSan[1]
			} else {
				return fmt.Errorf("Invalind subject alternate name")
			}
			sr.SAN = append(sr.SAN, _san)
		}
	}

	if *autoRenew {
		sr.AutoRenew = true
	}

	if *basicConstraint != "" {
		sr.BasicConstratint = make([]X509BasicConstraintData, 0)
		for _, bcd := range strings.Split(*basicConstraint, ",") {
			_bcd := X509BasicConstraintData{}
			rawBcd := strings.Split(bcd, ":")
			if len(rawBcd) == 2 {
				_bcd.Critical = false
				_bcd.Type = rawBcd[0]
				_bcd.Value = rawBcd[1]
			} else if len(rawBcd) == 3 {
				if rawBcd[0] == "" || rawBcd[1] == "0" {
					_bcd.Critical = false
				} else if rawBcd[0] == "1" {
					_bcd.Critical = true
				} else {
					return fmt.Errorf("Invalid basic constraint data")
				}
				_bcd.Type = rawBcd[1]
				_bcd.Value = rawBcd[2]
			} else {
				return fmt.Errorf("Invalid basic constraint data")
			}
			sr.BasicConstratint = append(sr.BasicConstratint, _bcd)
		}
	}

	if *keyUsage != "" {
		sr.KeyUsage = make([]X509KeyUsageData, 0)
		for _, kus := range strings.Split(*keyUsage, ",") {
			_kus := X509KeyUsageData{}
			rawKus := strings.Split(kus, ":")
			if len(rawKus) == 1 {
				_kus.Critical = false
				_kus.Type = rawKus[0]
			} else if len(rawKus) == 2 {
				if rawKus[0] == "" || rawKus[0] == "0" {
					_kus.Critical = false
				} else if rawKus[0] == "1" {
					_kus.Critical = true
				} else {
					return fmt.Errorf("Invalid key usage data")
				}
				_kus.Type = rawKus[1]
			} else {
				return fmt.Errorf("Invalid key usage data")
			}
			sr.KeyUsage = append(sr.KeyUsage, _kus)
		}
	}

	if *noRegister {
		sr.NoRegistration = true
	}

	if *startIn != 0 {
		sr.NotBefore = time.Now().Add(time.Duration(24) * time.Duration(*startIn) * time.Hour)
	} else {
		sr.NotBefore = time.Now()
	}

	validityPeriod = cfg.Global.ValidityPeriod
	if *template != "" {
	}

	if *validFor != 0 {
		if *validFor < 0 {
			return fmt.Errorf("Validity period can't be negative")
		}
		if *validFor > 0 {
			validityPeriod = *validFor
		}
	}

	sr.NotAfter = sr.NotBefore.Add(time.Duration(24) * time.Duration(validityPeriod) * time.Hour)

	if *output != "" {
	} else {
		fmt.Println()
	}

	return nil
}
