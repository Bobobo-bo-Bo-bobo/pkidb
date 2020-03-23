package main

import (
	"fmt"
	"net/http"
)

func writeOCSPResponse(out http.ResponseWriter, reply []byte) {
	out.Header().Set("Content-Type", "application/ocsp-response")
	_, err := out.Write(reply)
	if err != nil {
		LogMessage(config, LogLevelCritical, fmt.Sprintf("Can't send OCSP response to client: %s", err.Error()))
	}
}
