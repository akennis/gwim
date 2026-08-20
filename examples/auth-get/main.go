// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// auth-get is a minimal authenticated HTTP client — a curl-like tool
// for testing gwim's outbound transport against Windows-integrated-auth endpoints.
//
// Usage:
//
//	go run ./examples/auth-get --url https://ca01.corp.local/certsrv/
//	go run ./examples/auth-get --url https://ca01.corp.local/certsrv/ --spn HTTP/ca01.corp.local
//	go run ./examples/auth-get --url https://ca01.corp.local/certsrv/ --insecure
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/akennis/gwim"
)

func main() {
	target     := flag.String("url",          "", "URL to GET (required)")
	spn        := flag.String("spn",          "", "Kerberos SPN (default: HTTP/<host>)")
	insecure   := flag.Bool("insecure",       false, "Skip TLS certificate verification")
	noAuthTest := flag.Bool("no-auth-test",   false, "Send request with no credentials to verify the server rejects it")
	flag.Parse()

	if *target == "" {
		log.Fatal("--url is required")
	}
	u, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("invalid --url: %v", err)
	}
	if *spn == "" {
		*spn = "HTTP/" + u.Hostname()
	}

	base := baseTransport(*insecure)

	var client *http.Client
	if *noAuthTest {
		client = &http.Client{Transport: base, Timeout: 15 * time.Second}
	} else {
		rt, closer, err := gwim.NewNegotiateTransport(*spn, gwim.WithNTLMFallback(), gwim.WithClientBaseTransport(base))
		if err != nil {
			log.Fatalf("failed to create transport: %v", err)
		}
		defer closer.Close() //nolint:errcheck
		client = &http.Client{Transport: rt, Timeout: 15 * time.Second}
	}

	resp, err := client.Get(*target)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	fmt.Printf("Status : %s\n", resp.Status)
	if h := resp.Header.Get("WWW-Authenticate"); h != "" {
		fmt.Printf("WWW-Auth: %s\n", h)
	}
	if len(body) > 0 {
		fmt.Printf("\n%s\n", body)
	}
}

// baseTransport returns an HTTP/1.1-only transport suitable for Windows
// integrated authentication. IIS rejects HTTP/2 when Kerberos or NTLM is in
// use because both protocols bind auth state to the TCP connection.
func baseTransport(insecure bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	t.TLSClientConfig = &tls.Config{
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: insecure, //nolint:gosec
	}
	return t
}
