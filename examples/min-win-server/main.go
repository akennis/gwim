// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/akennis/gwim"
)

func main() {
	// CLI flags for configuration
	serverAddr := flag.String("server-addr", "localhost:8443", "The address[:port] the server will listen on")
	certSubject := flag.String("cert-subject", "localhost", "The subject of the certificate to use")
	certFromCurrentUser := flag.Bool("cert-from-current-user", false, "Whether to pull the certificate from the CurrentUser store instead of LocalMachine")
	useNTLM := flag.Bool("use-ntlm", false, "Use NTLM instead of Kerberos for authentication (required for non-domain or localhost scenarios)")
	ldapAddress := flag.String("ldap-address", "", "The address of the LDAP server")
	ldapUsersDN := flag.String("ldap-users-dn", "", "The DN for users in the LDAP server")
	ldapServiceAccountSPN := flag.String("ldap-service-account-spn", "", "The SPN for the service account in the LDAP server")
	flag.Parse()

	if err := runMinServer(*serverAddr, *certSubject, *certFromCurrentUser, *useNTLM, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN); err != nil {
		log.Fatal(err)
	}
}

func runMinServer(serverAddr, certSubject string, certFromCurrentUser, useNTLM bool, ldapAddress, ldapUsersDN, ldapServiceAccountSPN string) error {
	if ldapAddress == "" || ldapUsersDN == "" || ldapServiceAccountSPN == "" {
		log.Println("Warning: LDAP flags not set, group provider will be disabled.")
	}

	// Initialize router
	router := http.NewServeMux()
	router.HandleFunc("/", minRootHandler)

	// --- Apply Middleware (in reverse order of actual execution) ---
	var handler http.Handler = router
	log.Println("AUTHN/Z: Configuring middleware chain...")

	// LDAP Group Provider (Optional): Enriches context with group info.
	if ldapAddress != "" {
		ldapProvider, err := gwim.NewLDAPProvider(
			gwim.WithLDAPAddress(ldapAddress),
			gwim.WithLDAPUsersDN(ldapUsersDN),
			gwim.WithLDAPServiceAccountSPN(ldapServiceAccountSPN),
			gwim.WithLDAPErrorHandlers(gwim.AuthErrorHandlers{OnGeneralError: onMinAuthError}),
		)
		if err != nil {
			return fmt.Errorf("failed to create LDAP provider: %w", err)
		}
		handler = ldapProvider.Middleware(handler)
		log.Println("AUTHN/Z: --> Applied LDAP group provider")
	}

	// SSPI Provider: Performs Windows Authentication (Kerberos/NTLM).
	// This is the core of the gwim API.
	var sspiOpts []gwim.SSPIOption
	if useNTLM {
		sspiOpts = append(sspiOpts, gwim.WithNTLM())
	}
	sspiOpts = append(sspiOpts, gwim.WithSSPIErrorHandlers(gwim.AuthErrorHandlers{OnGeneralError: onMinAuthError}))
	sspiProvider, err := gwim.NewSSPIProvider(sspiOpts...)
	if err != nil {
		return fmt.Errorf("failed to create SSPI provider: %w", err)
	}
	handler = sspiProvider.Middleware(handler)
	log.Println("AUTHN/Z: --> Applied SSPI handler (Kerberos/NTLM)")

	// GetWin32Cert fetches the cert from the Windows store once at startup so
	// that any configuration error (wrong subject, expired cert, etc.) is caught
	// here rather than on the first TLS handshake.
	// Notes:
	// 1. resource cleanup not performed explicitly - cleaned by OS on proc exit
	// see examples/sec-win-server/main.go for explicit server shutdown and resource cleanup
	// 2. for zero downtime certificate rotation use gwim.GetCertificateFunc
	// see examples/sec-win-server/main.go for a usage reference
	certStore := gwim.CertStoreLocalMachine
	if certFromCurrentUser {
		certStore = gwim.CertStoreCurrentUser
	}
	certSource, err := gwim.GetWin32Cert(certSubject, certStore)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate %q: %w", certSubject, err)
	}

	srv := &http.Server{
		Addr:    serverAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certSource.Certificate},
			MinVersion:   tls.VersionTLS13,
		},
	}

	// NTLM requires specific connection handling on Windows.
	if useNTLM {
		gwim.ConfigureNTLM(srv)
	}

	log.Printf("Starting minimal secure server on https://%s", srv.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func onMinAuthError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("AUTHN/Z: [%s] Authentication failed: %v", r.RemoteAddr, err)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	data := struct {
		Error string
	}{
		Error: err.Error(),
	}
	if templateErr := minErrorTemplate.Execute(w, data); templateErr != nil {
		log.Printf("ERROR: failed to execute error handler template: %v", templateErr)
	}
}

var minErrorTemplate = template.Must(template.New("error").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Error</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding-top: 50px; }
        .error-box { display: inline-block; border: 1px solid #ff0000; padding: 20px; border-radius: 5px; background: #fff5f5; }
        h1 { color: #cc0000; }
    </style>
</head>
<body>
    <div class="error-box">
        <h1>Authentication Failed</h1>
        <p>An error occurred while trying to authenticate you.</p>
        <p><strong>Details:</strong> {{.Error}}</p>
    </div>
</body>
</html>
`))

var minRootTemplate = template.Must(template.New("root").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>GWIM Minimal Welcome</title>
</head>
<body>
    <h1>Hello, {{.Username}}!</h1>
    {{if .Groups}}
        <p>You belong to the following LDAP groups:</p>
        <ul>
            {{range .Groups}}
                <li>{{.}}</li>
            {{end}}
        </ul>
    {{else}}
        <p>You are authenticated via SSPI (Kerberos/NTLM).</p>
    {{end}}
</body>
</html>
`))

type minRootData struct {
	Username string
	Groups   []string
}

func minRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// gwim.User retrieves the authenticated username from the request context.
	username, ok := gwim.User(r)
	if !ok {
		log.Printf("AUTHN/Z: [%s] Unauthorized access to root handler.", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// gwim.UserGroups retrieves group memberships if the LDAP provider is active.
	groups, _ := gwim.UserGroups(r)
	log.Printf("AUTHN/Z: [%s] Root handler reached for user '%s'", r.RemoteAddr, username)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := minRootData{
		Username: username,
		Groups:   groups,
	}
	err := minRootTemplate.Execute(w, data)
	if err != nil {
		log.Printf("ERROR: failed to execute root handler template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
