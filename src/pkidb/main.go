package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"
)

var config *PKIConfiguration

func main() {
	var configFile = flag.String("config", DefaultConfigurationFile, "default configuration file if not specified otherwise")
	var site = flag.String("site", "", "")
	var help = flag.Bool("help", false, "Show help")
	var version = flag.Bool("version", false, "Show version information")
	var ok bool
	var command string
	var sites = make(map[string]*PKIConfiguration)
	var err error

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

	trailingArguments := flag.Args()
	if len(trailingArguments) == 0 {
		fmt.Fprintln(os.Stderr, "Not enough arguments")
		fmt.Fprintln(os.Stderr, "")
		showUsage()
		os.Exit(1)
	}

	config, err = ParseConfiguration(*configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = MergeEnvironment(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if config.Global.Sites != "" {
		sites, err = LoadSiteConfigurations(config.Global.Sites)
		if err != nil {
			LogMessage(config, LogLevelCritical, err.Error())
			os.Exit(1)
		}
	}

	if *site != "" {
		scfg, found := sites[*site]
		if !found {
			LogMessage(config, LogLevelCritical, fmt.Sprintf("%s: Can't find a configuration for site %s", GetFrame(), *site))
			os.Exit(1)
		}
		config = MergeSiteConfiguration(config, scfg)
	} else {
		// if sites are configured in the configuration file a default_site MUST be provided
		if config.Global.Sites != "" {
			if config.Global.DefaultSite != "" {
				LogMessage(config, LogLevelCritical, fmt.Sprintf("%s: sites are defined in %s but not default_site", GetFrame(), *configFile))
				os.Exit(1)
			}

			dcfg, found := sites[config.Global.DefaultSite]
			if !found {
				LogMessage(config, LogLevelCritical, fmt.Sprintf("%s: no configuration found for default_site %s", GetFrame(), config.Global.DefaultSite))
				os.Exit(1)
			}
			config = MergeSiteConfiguration(config, dcfg)
		}
	}

	FillConfigurationDefaults(config)
	err = ValidateConfiguration(config)
	if err != nil {
		LogMessage(config, LogLevelCritical, err.Error())
	}

	MaximumSerialNumber = new(big.Int)
	MaximumSerialNumber, ok = MaximumSerialNumber.SetString(MaximumSerialNumberString, 0)
	if !ok {
		LogMessage(config, LogLevelCritical, fmt.Sprintf("%s: Can't generate maximal serial number\n", GetFrame()))
		os.Exit(1)
	}

	command = trailingArguments[0]
	switch command {
	case "add-dummy":
		err = CmdAddDummy(config, trailingArguments[1:])
	case "backup":
		err = CmdBackup(config, trailingArguments[1:])
	case "delete":
		err = CmdDelete(config, trailingArguments[1:])
	case "export":
		err = CmdExport(config, trailingArguments[1:])
	case "gencrl":
		err = CmdGenCRL(config, trailingArguments[1:])
	case "housekeeping":
		err = CmdHousekeeping(config, trailingArguments[1:])
	case "import":
		err = CmdImport(config, trailingArguments[1:])
	case "list":
		err = CmdList(config, trailingArguments[1:])
	case "ocsp":
		err = CmdOcsp(config, trailingArguments[1:])
	case "renew":
		err = CmdRenew(config, trailingArguments[1:])
	case "restore":
		err = CmdRestore(config, trailingArguments[1:])
	case "revoke":
		err = CmdRevoke(config, trailingArguments[1:])
	case "search":
		err = CmdSearch(config, trailingArguments[1:])
	case "set":
		err = CmdSet(config, trailingArguments[1:])
	case "show":
		err = CmdShow(config, trailingArguments[1:])
	case "sign":
		err = CmdSign(config, trailingArguments[1:])
	case "statistics":
		err = CmdStatistics(config, trailingArguments[1:])
	default:
		fmt.Fprintln(os.Stderr, "Invalid command")
		fmt.Fprintln(os.Stderr, "")
		showUsage()
		os.Exit(1)
	}

	if err != nil {
		LogMessage(config, LogLevelCritical, err.Error())
	}

	err = config.DBBackend.CloseDatabase(config.Database.dbhandle)
	if err != nil {
		LogMessage(config, LogLevelCritical, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}
