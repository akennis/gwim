package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/akennis/gwim"
)

// --- Session Management ---

type Session struct {
	Username string
	Expiry   time.Time
}

var (
	sessionStore = make(map[string]Session)
	sessionMutex = &sync.RWMutex{}
	sessionTTL   = 15 * time.Minute // Sessions are valid for 15 minutes
)

const sessionCookieName = "sec-win-server-session"

// newSession creates a new session for the given username and returns the session ID.
func newSession(username string) string {
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	id := hex.EncodeToString(sessionID)

	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	sessionStore[id] = Session{
		Username: username,
		Expiry:   time.Now().Add(sessionTTL),
	}
	log.Printf("Created session %s for user %s", id, username)
	return id
}

// getSession returns the username from the session store if the session is valid.
func getSession(sessionID string) (string, bool) {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	session, found := sessionStore[sessionID]
	if !found || time.Now().After(session.Expiry) {
		if found {
			// Clean up expired session
			go func() {
				sessionMutex.Lock()
				defer sessionMutex.Unlock()
				delete(sessionStore, sessionID)
				log.Printf("Cleaned up expired session %s", sessionID)
			}()
		}
		return "", false
	}
	return session.Username, true
}

// --- HTTP Middleware ---

// sessionMiddleware checks for a valid session cookie. If found, it injects the
// user into the context, allowing the SSPI handler to be skipped.
func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			// No cookie, proceed to authentication
			next.ServeHTTP(w, r)
			return
		}

		username, ok := getSession(cookie.Value)
		if !ok {
			// Invalid or expired session, clear cookie and proceed to authentication
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1})
			next.ServeHTTP(w, r)
			return
		}

		// Valid session found, set user in context
		log.Printf("Found valid session for user %s", username)
		r = gwim.SetUser(r, username)
		next.ServeHTTP(w, r)
	})
}

// sessionPostAuthMiddleware runs after authentication. If a user was just authenticated
// (i.e., they have a username but no session yet), it creates a session for them.
func sessionPostAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if a session cookie already exists. If so, do nothing.
		if _, err := r.Cookie(sessionCookieName); err == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Check if authentication just completed by looking for the username.
		username, ok := gwim.User(r)
		if ok {
			// User was authenticated, create a session for them.
			sessionID := newSession(username)
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    sessionID,
				Expires:  time.Now().Add(sessionTTL),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
		}
		next.ServeHTTP(w, r)
	})
}

// --- Main Application ---

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

	useNTLM := *serverAddr == "localhost:8443" || *serverAddr == "localhost"

	// Initialize router
	router := http.NewServeMux()
	router.HandleFunc("/", rootHandler)

	// --- Apply Middleware (in reverse order of actual execution) ---
	var handler http.Handler = router

	// LDAP Group Provider: Enriches context with group info (runs after auth).
	if *ldapAddress != "" {
		handler = gwim.NewLdapGroupProvider(handler, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN)
	}

	// Post-Auth Session Creator: If SSPI just ran, this creates the session.
	handler = sessionPostAuthMiddleware(handler)

	// SSPI Handler: Performs Kerberos/NTLM auth if no user is in the context.
	handler, err := gwim.NewSSPIHandler(handler, useNTLM)
	if err != nil {
		log.Fatalf("Failed to create SSPI handler: %v", err)
	}

	// Session Middleware: The first handler to run. Checks for an existing session.
	handler = sessionMiddleware(handler)

	// Configure HTTPS server
	srv := &http.Server{
		Addr:    *serverAddr,
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
	username, ok := gwim.User(r)
	if !ok {
		// This should theoretically not be reached if middleware is correct
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	groups, _ := gwim.UserGroups(r)
	if len(groups) > 0 {
		fmt.Fprintf(w, "Hello, %s! Your LDAP groups are: %v", username, groups)
	} else {
		fmt.Fprintf(w, "Hello, %s! You have a valid session.", username)
	}
}
