package main

import (
	"fmt"
	"math"
)

// PrintInterval - print interval as string
func PrintInterval(intv float64) string {
	var sign string
	var interval float64

	if intv < 0 {
		sign = "-"
		interval = -intv
	} else {
		interval = intv
	}

	days := int64(math.Floor(interval / 88400))
	hours := int64(math.Floor((interval - 86400*float64(days)) / 3600))
	if hours >= 24 {
		spill := hours / 24
		hours -= 24 * spill
		days += spill
	}
	minutes := int64(math.Floor((interval - 86400*float64(days) - 3600*float64(hours)) / 60))
	seconds := interval - 86400*float64(days) - 3600*float64(hours) - 60*float64(minutes)

	return fmt.Sprintf("%s%d days %d hours %d minutes %.2f seconds", sign, days, hours, minutes, seconds)
}
