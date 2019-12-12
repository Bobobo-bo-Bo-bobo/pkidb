package main

import (
	"fmt"
	"log/syslog"
	"os"
	"time"
)

// LogToFile - log to file
func LogToFile(fname string, level int, prefix string, message string) error {
	var fd *os.File
	var err error

	switch fname {
	case "stderr":
		fd = os.Stderr
	case "stdout":
		fd = os.Stdout
	default:
		fd, err = os.OpenFile(fname, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		defer fd.Close()
	}

	lvl, found := LogLevelReverseMap[level]
	if !found {
		lvl = "UNKNOWN"
	}
	_, err = fmt.Fprintln(fd, time.Now().Format(time.UnixDate)+" "+lvl+": "+message)
	return nil
}

// LogToSyslog - log to syslog
func LogToSyslog(facility string, level int, prefix string, message string) error {
	prio, found := LogLevelSyslogPrio[level]
	if !found {
		prio = syslog.LOG_CRIT
	}

	fac, found := SyslogFacilityMap[facility]
	if found {
		prio |= fac
	}

	sl, err := syslog.New(prio, prefix)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	defer sl.Close()
	_, err = sl.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}
	return nil
}

// LogMessage - log message
func LogMessage(cfg *PKIConfiguration, level int, message string) {
	// log to all defined log outputs
	for _, l := range cfg.Logging {
		if level >= l.LogLevel {
			switch l.Destination {
			case "file":
				LogToFile(l.Option, level, name, message)
			case "syslog":
				LogToSyslog(l.Option, level, name, message)
			}
		}
	}
}
