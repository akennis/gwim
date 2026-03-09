package main

import (
	"crypto/tls"
	"flag"
	"html/template"
	"log"
	"net/http"

	"github.com/akennis/gwim"
	"github.com/akennis/gwim/auth"
)

func main() {
	// CLI flags for configuration
	serverAddr := flag.String("server-addr", "localhost:8443", "The address[:port] the server will listen on")
	certSubject := flag.String("cert-subject", "localhost", "The subject of the certificate to use")
	certFromCurrentUser := flag.Bool("cert-from-current-user", false, "Whether to pull the certificate from the CurrentUser store instead of LocalMachine")
	ldapAddress := flag.String("ldap-address", "", "The address of the LDAP server")
	ldapUsersDN := flag.String("ldap-users-dn", "", "The DN for users in the LDAP server")
	ldapServiceAccountSPN := flag.String("ldap-service-account-spn", "", "The SPN for the service account in the LDAP server")
	flag.Parse()

	if *ldapAddress == "" || *ldapUsersDN == "" || *ldapServiceAccountSPN == "" {
		log.Println("Warning: LDAP flags not set, group provider will be disabled.")
	}

	// Determine if NTLM should be enabled (usually for localhost/non-FQDN tests)
	useNTLM := *serverAddr == "localhost:8443" || *serverAddr == "localhost"

	// Initialize router
	router := http.NewServeMux()
	router.HandleFunc("/", minRootHandler)

	// --- Apply Middleware (in reverse order of actual execution) ---
	var handler http.Handler = router
	log.Println("AUTHN/Z: Configuring middleware chain...")

	// LDAP Group Provider (Optional): Enriches context with group info.
	if *ldapAddress != "" {
		handler = gwim.NewLdapGroupProvider(handler, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN, auth.AuthOptions{
			OnGeneralError: onMinAuthError,
		})
		log.Println("AUTHN/Z: --> Applied LDAP group provider")
	}

	// SSPI Handler: Performs Windows Authentication (Kerberos/NTLM).
	// This is the core of the gwim API.
	handler, err := gwim.NewSSPIHandler(handler, useNTLM, auth.AuthOptions{
		OnGeneralError: onMinAuthError,
	})
	if err != nil {
		log.Fatalf("Failed to create SSPI handler: %v", err)
	}
	log.Println("AUTHN/Z: --> Applied SSPI handler (Kerberos/NTLM)")

	// gwim provides a helper to retrieve a certificate from the Windows store for TLS
	certificate, err := gwim.GetCertificate(*certSubject, *certFromCurrentUser)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate: %v", err)
	}

	// Configure HTTPS server
	srv := &http.Server{
		Addr:    *serverAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		},
	}

	// NTLM requires specific connection handling on Windows.
	if useNTLM {
		gwim.ConfigureNTLM(srv)
	}

	log.Printf("Starting minimal secure server on https://%s", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
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
