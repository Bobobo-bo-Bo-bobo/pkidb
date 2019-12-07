package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseExtensionString - Get extension data from string
func ParseExtensionString(extensions string) ([]X509ExtensionData, error) {
	var result = make([]X509ExtensionData, 0)
	var err error

	for _, ext := range strings.Split(extensions, ",") {
		e := X509ExtensionData{}

		rawExt := strings.Split(ext, ":")
		if len(rawExt) != 3 {
			return nil, fmt.Errorf("Invalid extension data")
		}

		e.Name = rawExt[0]

		if rawExt[1] == "" || rawExt[1] == "0" {
			e.Critical = false
		} else if rawExt[1] == "1" {
			e.Critical = true
		} else {
			return nil, fmt.Errorf("Invalid extension data")
		}

		if rawExt[2] != "" {
			e.Data, err = base64.StdEncoding.DecodeString(rawExt[2])
			if err != nil {
				return nil, err
			}
		}
		result = append(result, e)
	}

	return result, nil
}
