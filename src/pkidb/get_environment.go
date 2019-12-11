package main

import (
	"os"
	"strings"
)

// GetEnvironment - Get environment variable as map
func GetEnvironment() map[string]string {
	var result = make(map[string]string)

	for _, env := range os.Environ() {
		kv := strings.SplitN(env, "=", 2)
		key := kv[0]
		value := kv[1]
		result[key] = value
	}

	return result
}
