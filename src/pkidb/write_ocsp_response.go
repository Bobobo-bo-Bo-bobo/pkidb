package main

import (
	"fmt"
	"net/http"
)

func writeOCSPResponse(out http.ResponseWriter, reply []byte) {
	out.Header().Set("Content-Type", "application/ocsp-response")
	fmt.Fprint(out, reply)
}
