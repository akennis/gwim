// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

// Command list-certs prints the subject (Common Name) of every certificate in
// the Windows "MY" certificate store, in the exact form it must be given to
// gwim.GetWin32Cert / gwim.GetCertificateFunc and to the -cert-subject flag of
// the example servers.
//
// gwim resolves a certificate with the Windows CERT_FIND_SUBJECT_STR search,
// which is a case-insensitive substring match against the certificate subject
// and returns the first match. This tool therefore also flags names that are
// ambiguous (a name that is a substring of another certificate's subject) or
// duplicated across certificates.
//
// Usage:
//
//	list-certs [-store localmachine|currentuser|both] [-all] [-json] [-verify=false]
//
// By default only certificates gwim can actually load are printed (unexpired,
// Server Authentication EKU, private key present, issuer chain trusted). Pass
// -all to print every certificate together with the reason it is unusable.
package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/akennis/gwim"
	"golang.org/x/sys/windows"
)

// record is one certificate found in a store.
type record struct {
	// Name is the value to pass to gwim (the certificate's Common Name).
	Name          string    `json:"name"`
	Store         string    `json:"store"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	HasServerAuth bool      `json:"hasServerAuthEKU"`
	HasPrivateKey bool      `json:"hasPrivateKey"`
	Usable        bool      `json:"usable"`
	// Problems lists reasons the name is unusable or risky to rely on.
	Problems []string `json:"problems,omitempty"`
	// VerifyError is gwim.GetWin32Cert's own error for this name, if -verify.
	VerifyError string `json:"verifyError,omitempty"`
}

func main() {
	storeArg := flag.String("store", "localmachine", "store to scan: localmachine, currentuser, or both")
	all := flag.Bool("all", false, "print every certificate, including ones gwim cannot load, with the reason")
	asJSON := flag.Bool("json", false, "emit JSON instead of text")
	verify := flag.Bool("verify", true, "confirm each name by actually calling gwim.GetWin32Cert")
	flag.Parse()

	var locs []string
	switch strings.ToLower(*storeArg) {
	case "both":
		locs = []string{"localmachine", "currentuser"}
	default:
		locs = []string{*storeArg}
	}

	var recs []record
	for _, loc := range locs {
		locFlag, name, ok := storeLocation(loc)
		if !ok {
			fmt.Fprintf(os.Stderr, "list-certs: unknown -store %q (want localmachine, currentuser, or both)\n", loc)
			os.Exit(2)
		}
		r, err := enumerate(locFlag, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list-certs: %v\n", err)
			os.Exit(1)
		}
		recs = append(recs, r...)
	}

	annotate(recs)
	if *verify {
		runVerify(recs)
	}
	for i := range recs {
		rec := &recs[i]
		if *verify {
			rec.Usable = rec.Name != "" && rec.VerifyError == ""
		} else {
			rec.Usable = len(rec.Problems) == 0
		}
	}

	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Store != recs[j].Store {
			return recs[i].Store < recs[j].Store
		}
		return strings.ToLower(recs[i].Name) < strings.ToLower(recs[j].Name)
	})

	if *asJSON {
		emitJSON(recs, *all)
		return
	}
	emitText(recs, *all)
}

// storeLocation maps a CLI store name to its CERT_SYSTEM_STORE_* flag and the
// label gwim uses for it.
func storeLocation(name string) (locFlag uint32, label string, ok bool) {
	switch strings.ToLower(name) {
	case "localmachine", "lm", "machine":
		return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, "LocalMachine", true
	case "currentuser", "cu", "user":
		return windows.CERT_SYSTEM_STORE_CURRENT_USER, "CurrentUser", true
	}
	return 0, "", false
}

// enumerate walks the "MY" store at the given location and returns one record
// per certificate it can parse.
func enumerate(locFlag uint32, label string) ([]record, error) {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return nil, err
	}
	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		locFlag|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(storeName)),
	)
	runtime.KeepAlive(storeName)
	if err != nil {
		return nil, fmt.Errorf("open %s\\MY: %w", label, err)
	}
	defer windows.CertCloseStore(h, 0)

	var recs []record
	var ctx *windows.CertContext
	for {
		// CertEnumCertificatesInStore frees the context passed in and returns
		// the next one; at the end it returns nil with CRYPT_E_NOT_FOUND.
		ctx, err = windows.CertEnumCertificatesInStore(h, ctx)
		if ctx == nil {
			break
		}

		der := make([]byte, ctx.Length)
		copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
		cert, perr := x509.ParseCertificate(der)
		if perr != nil {
			continue // skip anything that is not a parseable X.509 cert
		}

		rec := record{
			Name:          cert.Subject.CommonName,
			Store:         label,
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			NotBefore:     cert.NotBefore,
			NotAfter:      cert.NotAfter,
			HasServerAuth: serverAuthOK(cert),
			HasPrivateKey: hasPrivateKey(ctx),
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// serverAuthOK reports whether the certificate satisfies the ServerAuth EKU
// check that gwim's x509.Verify call applies: an explicit ServerAuth or Any
// usage, or no EKU extension at all.
func serverAuthOK(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

var procNCryptFreeObject = windows.NewLazySystemDLL("ncrypt.dll").NewProc("NCryptFreeObject")

// hasPrivateKey reports whether a usable private key is bound to the cert.
func hasPrivateKey(ctx *windows.CertContext) bool {
	var kh windows.Handle
	var keySpec uint32
	var callerFree bool
	err := windows.CryptAcquireCertificatePrivateKey(
		ctx,
		windows.CRYPT_ACQUIRE_SILENT_FLAG,
		nil,
		&kh,
		&keySpec,
		&callerFree,
	)
	if err != nil {
		return false
	}
	if callerFree && kh != 0 {
		if keySpec == windows.CERT_NCRYPT_KEY_SPEC {
			procNCryptFreeObject.Call(uintptr(kh))
		} else {
			windows.CryptReleaseContext(kh, 0)
		}
	}
	return true
}

// annotate fills in each record's Problems slice.
func annotate(recs []record) {
	now := time.Now()
	for i := range recs {
		rec := &recs[i]
		if rec.Name == "" {
			rec.Problems = append(rec.Problems, "no Common Name; gwim cannot address this certificate by subject")
		}
		if now.Before(rec.NotBefore) {
			rec.Problems = append(rec.Problems, "not yet valid (NotBefore "+rec.NotBefore.Format(time.RFC3339)+")")
		}
		if now.After(rec.NotAfter) {
			rec.Problems = append(rec.Problems, "expired ("+rec.NotAfter.Format(time.RFC3339)+")")
		}
		if !rec.HasServerAuth {
			rec.Problems = append(rec.Problems, "missing Server Authentication EKU")
		}
		if !rec.HasPrivateKey {
			rec.Problems = append(rec.Problems, "no accessible private key")
		}
	}

	// Flag names that CERT_FIND_SUBJECT_STR cannot resolve unambiguously.
	for i := range recs {
		a := &recs[i]
		if a.Name == "" {
			continue
		}
		needle := strings.ToLower(a.Name)
		for j := range recs {
			if i == j || recs[j].Store != a.Store {
				continue
			}
			other := recs[j]
			if !strings.Contains(strings.ToLower(other.Subject), needle) {
				continue
			}
			if strings.EqualFold(a.Name, other.Name) {
				a.Problems = append(a.Problems, "duplicate Common Name in "+a.Store+"; gwim uses whichever the store lists first")
			} else {
				a.Problems = append(a.Problems, "ambiguous: substring of another subject ("+other.Subject+"); gwim may match either")
			}
			break
		}
	}
}

// runVerify asks gwim itself to load every distinct (name, store) pair.
func runVerify(recs []record) {
	for i := range recs {
		rec := &recs[i]
		if rec.Name == "" {
			continue
		}
		store := gwim.CertStoreLocalMachine
		if rec.Store == "CurrentUser" {
			store = gwim.CertStoreCurrentUser
		}
		src, err := gwim.GetWin32Cert(rec.Name, store)
		if err != nil {
			rec.VerifyError = err.Error()
			continue
		}
		src.Close()
	}
}

func emitJSON(recs []record, all bool) {
	out := recs
	if !all {
		out = make([]record, 0, len(recs))
		for _, rec := range recs {
			if rec.Usable {
				out = append(out, rec)
			}
		}
	}
	if out == nil {
		out = []record{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "list-certs: %v\n", err)
		os.Exit(1)
	}
}

func emitText(recs []record, all bool) {
	shown := 0
	for _, rec := range recs {
		if !all && !rec.Usable {
			continue
		}
		if shown == 0 {
			fmt.Println("Pass the name below as gwim.GetWin32Cert's subject / the -cert-subject flag.")
			fmt.Println()
		}
		shown++

		name := rec.Name
		if name == "" {
			name = "(no Common Name)"
		}
		status := "OK"
		if !rec.Usable {
			status = "UNUSABLE"
		}
		fmt.Printf("%s\t[%s %s]\n", name, rec.Store, status)
		fmt.Printf("    subject : %s\n", rec.Subject)
		fmt.Printf("    issuer  : %s\n", rec.Issuer)
		fmt.Printf("    valid   : %s .. %s\n",
			rec.NotBefore.Format(time.RFC3339), rec.NotAfter.Format(time.RFC3339))
		if rec.VerifyError != "" {
			fmt.Printf("    gwim    : %s\n", rec.VerifyError)
		}
		for _, p := range rec.Problems {
			fmt.Printf("    warn    : %s\n", p)
		}
		fmt.Println()
	}

	if shown == 0 {
		if all {
			fmt.Println("No certificates found in the selected store(s).")
		} else {
			fmt.Println("No certificates in the selected store(s) can be loaded by gwim. Re-run with -all for details.")
		}
	}
}
