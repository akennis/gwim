package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/akennis/gwim"
)

func main() {
	// CLI flags for configuration
	serverAddr := flag.String("server-addr", "", "The address the server will listen on")
	secureServerPort := flag.Int("secure-server-port", 0, "The port the secure server will listen on")
	certSubject := flag.String("cert-subject", "", "The subject of the certificate to use")
	ldapAddress := flag.String("ldap-address", "", "The address of the LDAP server")
	ldapUsersDN := flag.String("ldap-users-dn", "", "The DN for users in the LDAP server")
	ldapServiceAccountSPN := flag.String("ldap-service-account-spn", "", "The SPN for the service account in the LDAP server")
	flag.Parse()

	if *serverAddr == "" || *secureServerPort == 0 || *certSubject == "" || *ldapAddress == "" || *ldapUsersDN == "" || *ldapServiceAccountSPN == "" {
		flag.Usage()
		log.Fatal("All flags are required")
	}

	useNTLM := *serverAddr == "localhost"

	// Initialize router
	router := http.NewServeMux()
	router.HandleFunc("/", rootHandler)

	// --- Apply Middleware ---
	handler, err := gwim.NewSSPIHandler(router, useNTLM)
	if err != nil {
		log.Fatalf("Failed to create SSPI handler: %v", err)
	}
	handler = gwim.NewLdapGroupProvider(handler, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN)

	// Configure HTTPS server
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", *serverAddr, *secureServerPort),
		Handler: handler,
	}

	if useNTLM {
		gwim.ConfigureNTLM(srv)
	}

	if err := gwim.ConfigureTLS(srv, *certSubject); err != nil {
		log.Fatalf("Failed to configure TLS: %v", err)
	}

	log.Printf("Starting secure server on https://%s", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	username, groups, ok := gwim.User(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "Hello, %s! Your LDAP groups are: %v", username, groups)
}
