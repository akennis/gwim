package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"

	"github.com/akennis/gwim"
)

func main() {
	// CLI flags for configuration
	serverAddr := flag.String("server-addr", "localhost:8443", "The address[:port] the server will listen on")
	certSubject := flag.String("cert-subject", "localhost", "The subject of the certificate to use")
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
	router.HandleFunc("/", rootHandler)

	// --- Apply Middleware (in reverse order of actual execution) ---
	var handler http.Handler = router
	log.Println("AUTHN/Z: Configuring middleware chain...")

	// LDAP Group Provider (Optional): Enriches context with group info.
	if *ldapAddress != "" {
		handler = gwim.NewLdapGroupProvider(handler, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN)
		log.Println("AUTHN/Z: --> Applied LDAP group provider")
	}

	// SSPI Handler: Performs Windows Authentication (Kerberos/NTLM).
	// This is the core of the gwim API.
	handler, err := gwim.NewSSPIHandler(handler, useNTLM)
	if err != nil {
		log.Fatalf("Failed to create SSPI handler: %v", err)
	}
	log.Println("AUTHN/Z: --> Applied SSPI handler (Kerberos/NTLM)")

	// Configure HTTPS server
	srv := &http.Server{
		Addr:    *serverAddr,
		Handler: handler,
	}

	// NTLM requires specific connection handling on Windows.
	if useNTLM {
		gwim.ConfigureNTLM(srv)
	}

	// gwim provides a helper to configure TLS with a self-signed or existing cert.
	if err := gwim.ConfigureTLS(srv, *certSubject); err != nil {
		log.Fatalf("Failed to configure TLS: %v", err)
	}

	log.Printf("Starting minimal secure server on https://%s", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

var parsedRootTemplate = template.Must(template.New("root").Parse(`
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

type rootData struct {
	Username string
	Groups   []string
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
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
	data := rootData{
		Username: username,
		Groups:   groups,
	}
	err := parsedRootTemplate.Execute(w, data)
	if err != nil {
		log.Printf("ERROR: failed to execute root handler template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
