// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"

	"github.com/akennis/gwim"
)

func main() {
	serverAddr         := flag.String("server-addr",           "localhost:8443", "The address[:port] the server will listen on")
	certSubject        := flag.String("cert-subject",          "localhost",      "The subject of the certificate to use")
	certFromCurrentUser := flag.Bool("cert-from-current-user", false,            "Whether to pull the certificate from the CurrentUser store instead of LocalMachine")
	useNTLM            := flag.Bool("use-ntlm",                false,            "Use NTLM instead of Kerberos (required for non-domain or localhost scenarios)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		username, _ := gwim.User(r)
		w.Write([]byte("Hello, " + username))
	})

	var sspiOpts []gwim.SSPIOption
	if *useNTLM {
		sspiOpts = append(sspiOpts, gwim.WithNTLM())
	}
	sspiProvider, err := gwim.NewSSPIProvider(sspiOpts...)
	if err != nil {
		log.Fatal(err)
	}

	certStore := gwim.CertStoreLocalMachine
	if *certFromCurrentUser {
		certStore = gwim.CertStoreCurrentUser
	}
	certSource, err := gwim.GetWin32Cert(*certSubject, certStore)
	if err != nil {
		log.Fatal(err)
	}
	defer certSource.Close()

	srv := &http.Server{
		Addr:    *serverAddr,
		Handler: sspiProvider.Middleware(mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certSource.Certificate},
		},
	}

	if *useNTLM {
		gwim.ConfigureNTLM(srv)
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}
