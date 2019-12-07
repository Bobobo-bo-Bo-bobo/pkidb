package main

import (
	"fmt"
	"runtime"
)

func showVersion() {
	fmt.Printf("%s version %s\n"+
		"Copyright (C) by Andreas Maus <maus@ypbind.de>\n"+
		"This program comes with ABSOLUTELY NO WARRANTY.\n"+
		"\n"+
		"%s is distributed under the Terms of the GNU General\n"+
		"Public License Version 3. (http://www.gnu.org/copyleft/gpl.html)\n"+
		"\n"+
		"Build with go version: %s\n\n", name, version, name, runtime.Version())
}
