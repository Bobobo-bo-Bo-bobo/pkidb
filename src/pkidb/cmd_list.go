package main

import (
	"flag"
	"fmt"
	"os"
)

// CmdList - list command
func CmdList(cfg *PKIConfiguration, args []string) error {
	var state = ListAllSerialNumbers
	var outlist string
	var fd *os.File

	argParse := flag.NewFlagSet("cmd-list", flag.ExitOnError)
	var output = argParse.String("output", "", "Write certificate information to <output> instead of standard output")
	var expired = argParse.Bool("expired", false, "List serial numbers of expired certificates")
	var invalid = argParse.Bool("invalid", false, "List serial numbers of invalid certificates")
	var revoked = argParse.Bool("revoked", false, "List serial numbers of revoked certificates")
	var temporary = argParse.Bool("temporary", false, "List \"certificates\" marked as temporary")
	var valid = argParse.Bool("valid", false, "List serial numbers of valid certificates")
	argParse.Usage = showHelpList
	argParse.Parse(args)

	cmdListTrailing := argParse.Args()
	if len(cmdListTrailing) > 0 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	if *expired {
		state = PKICertificateStatusExpired
	}

	if *invalid {
		state = PKICertificateStatusInvalid
	}

	if *revoked {
		state = PKICertificateStatusRevoked
	}

	if *temporary {
		state = PKICertificateStatusTemporary
	}

	if *valid {
		state = PKICertificateStatusValid
	}

	list, err := cfg.DBBackend.GetSerialNumbersByState(cfg, state)
	if err != nil {
		return err
	}

	if *output == "" {
		fd = os.Stdout
	} else {
		fd, err = os.Create(*output)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	for _, sn := range list {
		if cfg.Global.ListAsHex {
			outlist += fmt.Sprintf("0x%s\n", sn.Text(16))
		} else {
			outlist += fmt.Sprintf("%s\n", sn.Text(10))
		}
	}

	_, err = fmt.Fprintf(fd, "%s", outlist)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if *output != "" {
		err = fd.Close()
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	return nil
}
