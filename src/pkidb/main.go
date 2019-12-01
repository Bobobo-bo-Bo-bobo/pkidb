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

	if *configFile != "" {
	}

	trailingArguments := flag.Args()
	if len(trailingArguments) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Not enough arguments")
		fmt.Fprintln(os.Stderr, "")
		showUsage()
		os.Exit(1)
	}

	MaximumSerialNumber = new(big.Int)
	MaximumSerialNumber, ok = MaximumSerialNumber.SetString(MaximumSerialNumberString, 0)
	if !ok {
		log.WithFields(log.Fields{"maximum_serial_number_string": MaximumSerialNumberString}).Fatal("Can't generate maximal serial number")
	}
}
