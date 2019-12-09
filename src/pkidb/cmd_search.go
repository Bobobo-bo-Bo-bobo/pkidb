package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// CmdSearch - search certificate subject
func CmdSearch(cfg *PKIConfiguration, args []string) error {
	var srchList = make([]string, 0)
	var splitted []string
	var out string
	var fd *os.File
	var err error

	argParse := flag.NewFlagSet("cmd-search", flag.ExitOnError)
	var output = argParse.String("output", "", "Write certificate information to <output> instead of standard output")
	argParse.Usage = showHelpSearch
	argParse.Parse(args)

	cmdSearchTrailing := argParse.Args()
	if len(cmdSearchTrailing) == 0 {
		raw, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
            return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		rawstr := string(raw)
		rawstr = strings.Replace(rawstr, "\r", "", -1)
		rawstr = strings.Replace(rawstr, "\n", " ", -1)
		rawstr = strings.Replace(rawstr, "\t", " ", -1)

		splitted = strings.Split(rawstr, " ")
	} else {
		splitted = cmdSearchTrailing
	}

	for _, v := range splitted {
		if strings.TrimSpace(v) != "" {
			srchList = append(srchList, strings.TrimSpace(v))
		}
	}

	for _, srch := range srchList {
		serial, err := cfg.DBBackend.SearchSubject(cfg, srch)
		if err != nil {
            return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}

		if serial != nil {
			if cfg.Global.ListAsHex {
				out += fmt.Sprintf("0x%s\n", serial.Text(16))
			} else {
				out += fmt.Sprintf("%s\n", serial.Text(10))
			}
		}
	}

	if *output == "" {
		fd = os.Stdout
	} else {
		fd, err = os.Create(*output)
		if err != nil {
            return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
	}

	_, err = fmt.Fprintf(fd, "%s", out)
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
