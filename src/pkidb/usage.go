package main

import (
	"fmt"
	"sort"
)

func showUsage() {
	showVersion()
	fmt.Printf(HelpText, name, DefaultConfigurationFile)

	cmds := make([]string, 0)
	for key := range HelpTextMap {
		cmds = append(cmds, key)
	}
	sort.Strings(cmds)

	for _, c := range cmds {
		showHelp(c, false)
	}
}

func showHelp(command string, copyright bool) {
	text, found := HelpTextMap[command]
	if found {
		if copyright {
			showVersion()
		}
		fmt.Println(text)
	}
}

func showHelpAddDummy() {
	showHelp("add-dummy", true)
}
func showHelpBackup() {
	showHelp("backup", true)
}
func showHelpDelete() {
	showHelp("delete", true)
}
func showHelpExport() {
	showHelp("export", true)
}
func showHelpGenCRL() {
	showHelp("gencrl", true)
}
func showHelpHealthcheck() {
	showHelp("healthcheck", true)
}
func showHelpHousekeeping() {
	showHelp("housekeeping", true)
}
func showHelpImport() {
	showHelp("import", true)
}
func showHelpList() {
	showHelp("list", true)
}
func showHelpRenew() {
	showHelp("renew", true)
}
func showHelpRestore() {
	showHelp("restore", true)
}
func showHelpRevoke() {
	showHelp("revoke", true)
}
func showHelpSearch() {
	showHelp("search", true)
}
func showHelpSet() {
	showHelp("set", true)
}
func showHelpShow() {
	showHelp("show", true)
}
func showHelpSign() {
	showHelp("sign", true)
}
func showHelpStatistics() {
	showHelp("statistics", true)
}
