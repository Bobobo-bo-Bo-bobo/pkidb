package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
)

// CmdOcsp - Start web server for handling of OCSP requests
func CmdOcsp(cfg *PKIConfiguration, args []string) error {
	var err error

	argParse := flag.NewFlagSet("cmd-ocsp", flag.ExitOnError)
	var uri = argParse.String("uri", "", "Listen and process OCEP requests on <uri>")
	argParse.Usage = showHelpOcsp
	argParse.Parse(args)

	cmdOcspTrailing := argParse.Args()
	if len(cmdOcspTrailing) > 0 {
		return fmt.Errorf("%s: Too many arguments", GetFrame())
	}

	if *uri != "" {
		cfg.Global.OcspURI = *uri
	}

	if cfg.Global.OcspURI == "" {
		return fmt.Errorf("%s: No OCSP URI configured", GetFrame())
	}

	if cfg.OCSPPublicKey == nil || cfg.OCSPCertificate == nil {
		return fmt.Errorf("%s: No public/private key for OCSP signing", GetFrame())
	}

	// validate URI
	_uri, err := url.Parse(cfg.Global.OcspURI)
	if err != nil {
		return fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	if _uri.Scheme != "http" {
		return fmt.Errorf("%s: Unsupported scheme %s", GetFrame(), _uri.Scheme)
	}

	cfg.OCSP.Address = _uri.Host

	if _uri.Path == "" {
		cfg.OCSP.Path = "/"
	} else {
		cfg.OCSP.Path = _uri.Path
	}

	// start HTTP listener
	http.HandleFunc(cfg.OCSP.Path, ocspHandler)

	// ListenAndServe always returns a non-nil error
	http.ListenAndServe(cfg.OCSP.Address, nil)

	return nil
}
