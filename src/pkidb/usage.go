package main

import (
	"fmt"
)

func showUsage() {
	showVersion()
	fmt.Printf(HelpText, name, DefaultConfigurationFile)
}
