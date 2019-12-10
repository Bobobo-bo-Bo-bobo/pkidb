package main

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// GetFrame - get caller (file, line, function)
func GetFrame() string {
	callers := make([]uintptr, 15)

	// get function stack, skip first two entries (our stack and return stack)
	count := runtime.Callers(2, callers)

	// get frames
	stackFrame := runtime.CallersFrames(callers[:count])

	// we don't care if there are more frames
	frame, _ := stackFrame.Next()

	function := frame.Function
	if function == "" {
		function = "???"
	}
	file := frame.File
	if file == "" {
		file = "???.go"
	}

	if frame.Line == 0 {
		return fmt.Sprintf("%s:?:%s", filepath.Base(file), frame.Function)
	}

	return fmt.Sprintf("%s:%d:%s", filepath.Base(file), frame.Line, frame.Function)
}
