package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// CmdOcsp - Start web server for handling of OCSP requests
func CmdOcsp(cfg *PKIConfiguration, args []string) error {
	var err error
	var tlsCfg *tls.Config

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

	if _uri.Scheme != "http" && _uri.Scheme != "https" {
		return fmt.Errorf("%s: Unsupported scheme %s", GetFrame(), _uri.Scheme)
	}

	router := mux.NewRouter()
	subRouterGET := router.Methods("GET").Subrouter()
	subRouterPOST := router.Methods("POST").Subrouter()

	/* XXX: RFC 6960 make it optional to support https scheme:
	 *
	 *   "Where privacy is a requirement, OCSP transactions exchanged using HTTP MAY be
	 *    protected using either Transport Layer Security/Secure Socket Layer
	 *    (TLS/SSL) or some other lower-layer protocol."
	 * (see RFC6960, Section A.1)
	 *
	 */
	router.Host(_uri.Host)

	// Used for HTTP POST
	if _uri.Path == "" {
		subRouterPOST.HandleFunc("/", ocspHandler)
	} else {
		subRouterPOST.HandleFunc(_uri.Path, ocspHandler)
	}

	// Used for HTTP GET
	/*
	 * RFC6960, Section A.1 defines the format of the GET request as:
	 *
	 *  "An OCSP request using the GET method is constructed as follows:
	 *   GET {url}/{url-encoding of base-64 encoding of the DER encoding of
	 *   the OCSPRequest} where {url} may be derived from the value of the authority
	 *   information access extension in the certificate being checked for
	 *   revocation, or other local configuration of the OCSP client."
	 *
	 */
	// Note: It's tempting to use filepath.Join() instead but this will produce incorrect
	//       string on Windows, because on Windows the separator is "\" instead of "/".
	// _trimmed := strings.TrimRight(_uri.Path, "/")+"/{ocsp_get_payload:.*}"
	_trimmed := strings.TrimRight(_uri.Path, "/") + "/{ocsp_get_payload:[A-Za-z0-9/=+]+}"
	subRouterGET.HandleFunc(_trimmed, ocspHandler)

	cfg.OCSP.Address = _uri.Host

	if _uri.Path == "" {
		cfg.OCSP.Path = "/"
	} else {
		cfg.OCSP.Path = _uri.Path
	}

	httpSrv := &http.Server{
		Addr:         _uri.Host,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  60 * time.Second,
		Handler:      router,
	}

	if _uri.Scheme == "https" {
		tlsCfg, err = generateTLSConfiguration(cfg)
		if err != nil {
			return fmt.Errorf("%s: %s", GetFrame(), err.Error())
		}
		httpSrv.TLSConfig = tlsCfg
		httpSrv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)
	}

	// start HTTP server in background to listen for signals and gracefully shutdown the server
	go func() {
		if _uri.Scheme == "https" {
			err = httpSrv.ListenAndServeTLS(cfg.Global.OcspServerPublicKey, cfg.Global.OcspServerPrivateKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil {
			LogMessage(cfg, LogLevelCritical, fmt.Sprintf("%s: %s", GetFrame(), err.Error()))
		}
	}()

	// listen for signals
	sigChan := make(chan os.Signal, 1)

	// Listen for SIGINT, SIGKILL and SIGTERM signals
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	<-sigChan
	_ctx, _cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer _cancel()

	// This will shutdown the server immediately if no connection is present, otherwise wait for 15 seconds
	httpSrv.Shutdown(_ctx)

	return nil
}

func generateTLSConfiguration(cfg *PKIConfiguration) (*tls.Config, error) {
	if cfg.Global.OcspServerPublicKey == "" || cfg.Global.OcspServerPrivateKey == "" {
		return nil, fmt.Errorf("%s: No server certificate files provided", GetFrame())
	}

	result := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	return result, nil
}
