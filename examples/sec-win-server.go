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
	Username     string
	Expiry       time.Time
	Groups       []string
	GroupsExpiry time.Time
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

// getSession returns the session from the session store if the session is valid.
func getSession(sessionID string) (Session, bool) {
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
		return Session{}, false
	}
	return session, true
}

// updateSessionWithGroups updates the session store with the user's group memberships.
func updateSessionWithGroups(sessionID string, groups []string) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if session, found := sessionStore[sessionID]; found {
		session.Groups = groups
		session.GroupsExpiry = time.Now().Add(5 * time.Minute)
		sessionStore[sessionID] = session
		log.Printf("Cached groups for user %s in session %s", session.Username, sessionID)
	}
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

		session, ok := getSession(cookie.Value)
		if !ok {
			// Invalid or expired session, clear cookie and proceed to authentication
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1})
			next.ServeHTTP(w, r)
			return
		}

		// Valid session found, set user in context
		log.Printf("Found valid session for user %s", session.Username)
		r = gwim.SetUser(r, session.Username)

		// If the session has valid cached groups, inject them into the context
		if session.Groups != nil && time.Now().Before(session.GroupsExpiry) {
			log.Printf("Found valid cached groups for user %s", session.Username)
			r = gwim.SetUserGroups(r, session.Groups)
		}

		next.ServeHTTP(w, r)
	})
}

// sessionPostAuthMiddleware runs after authentication and after the LDAP group
// provider. It creates a session for a newly authenticated user and caches any
// group memberships that were just fetched.
func sessionPostAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First, handle session creation if needed.
		// This happens if a user was just authenticated and has no session cookie.
		if _, err := r.Cookie(sessionCookieName); err != nil {
			if username, ok := gwim.User(r); ok {
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
				// The request cookie jar is not updated automatically
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
			}
		}

		// Now, handle group caching.
		// This happens after the LdapGroupProvider has run.
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			if session, ok := getSession(cookie.Value); ok {
				// If the session doesn't have groups or they are expired, check the context.
				if session.Groups == nil || time.Now().After(session.GroupsExpiry) {
					if groups, ok := gwim.UserGroups(r); ok {
						updateSessionWithGroups(cookie.Value, groups)
					}
				}
			}
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

	// Post-Auth Session Creator: If SSPI just ran, this creates the session.
	handler = sessionPostAuthMiddleware(handler)

	// LDAP Group Provider: Enriches context with group info (runs after auth).
	if *ldapAddress != "" {
		handler = gwim.NewLdapGroupProvider(handler, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN)
	}

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
