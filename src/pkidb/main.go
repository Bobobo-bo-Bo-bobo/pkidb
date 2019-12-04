package main

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math/big"
	"os"
	"time"
)

func main() {
	var configFile = flag.String("config", DefaultConfigurationFile, "default configuration file if not specified otherwise")
	var site = flag.String("site", "", "")
	var help = flag.Bool("help", false, "Show help")
	var version = flag.Bool("version", false, "Show version information")
	var ok bool
	var config *PKIConfiguration
	var command string

	var logFmt = new(log.TextFormatter)
	logFmt.FullTimestamp = true
	logFmt.TimestampFormat = time.RFC3339
	log.SetFormatter(logFmt)

	flag.Usage = showUsage
	flag.Parse()

	if *help {
		showUsage()
		os.Exit(0)
	}

	if *version {
		showVersion()
		os.Exit(0)
	}

	if *site != "" {
	}

	trailingArguments := flag.Args()
	if len(trailingArguments) == 0 {
		fmt.Fprintln(os.Stderr, "Not enough arguments")
		fmt.Fprintln(os.Stderr, "")
		showUsage()
		os.Exit(1)
	}

	MaximumSerialNumber = new(big.Int)
	MaximumSerialNumber, ok = MaximumSerialNumber.SetString(MaximumSerialNumberString, 0)
	if !ok {
		log.WithFields(log.Fields{"maximum_serial_number_string": MaximumSerialNumberString}).Fatal("Can't generate maximal serial number")
	}

	config, err := ParseConfiguration(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't parse configuration file: %s\n", err)
		os.Exit(1)
	}
	command = trailingArguments[0]
	switch command {
	case "add-dummy":
		err = CmdAddDummy(config, trailingArguments[1:])
	case "delete":
		err = CmdDelete(config, trailingArguments[1:])
	case "export":
		err = CmdExport(config, trailingArguments[1:])
	case "import":
		err = CmdImport(config, trailingArguments[1:])
	case "revoke":
		err = CmdRevoke(config, trailingArguments[1:])
	case "search":
		err = CmdSearch(config, trailingArguments[1:])
	case "show":
		err = CmdShow(config, trailingArguments[1:])
	case "sign":
		err = CmdSign(config, trailingArguments[1:])
	default:
		fmt.Fprintln(os.Stderr, "Invalid command")
		fmt.Fprintln(os.Stderr, "")
		showUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
