package main

import (
	"context"
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

const sessionAuthKey = "session-authenticated"

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

// regenerateSession clears the old session and creates a new one for the user. It returns the new session ID.
func regenerateSession(w http.ResponseWriter, r *http.Request, username string) string {
	// If a cookie exists, delete the old session it points to.
	if oldCookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionMutex.Lock()
		delete(sessionStore, oldCookie.Value)
		sessionMutex.Unlock()
		log.Printf("Regenerating session: Deleted old session %s", oldCookie.Value)
	}

	// Create a new session.
	sessionID := newSession(username)

	// Set the new session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Expires:  time.Now().Add(sessionTTL),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Update the request's cookie jar so subsequent middleware sees the new session.
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})

	log.Printf("Regenerated session: New session is %s for user %s", sessionID, username)
	return sessionID
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
		log.Printf("AUTHN/Z: [%s] Request received. Entering session middleware.", r.RemoteAddr)
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			// No cookie, proceed to authentication
			log.Printf("AUTHN/Z: [%s] No session cookie. Proceeding to SSPI authentication.", r.RemoteAddr)
			next.ServeHTTP(w, r)
			return
		}

		session, ok := getSession(cookie.Value)
		if !ok {
			// Invalid or expired session, clear cookie and proceed to authentication
			log.Printf("AUTHN/Z: [%s] Invalid or expired session. Proceeding to SSPI authentication.", r.RemoteAddr)
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1})
			next.ServeHTTP(w, r)
			return
		}

		// Valid session found, set user in context
		log.Printf("AUTHN/Z: [%s] Found valid session for user '%s'. Skipping SSPI.", r.RemoteAddr, session.Username)
		r = gwim.SetUser(r, session.Username)
		// Mark in the context that authentication came from a valid session.
		r = r.WithContext(context.WithValue(r.Context(), sessionAuthKey, true))

		// If the session has valid cached groups, inject them into the context
		if session.Groups != nil && time.Now().Before(session.GroupsExpiry) {
			log.Printf("AUTHN/Z: [%s] Found valid cached groups for user '%s'.", r.RemoteAddr, session.Username)
			r = gwim.SetUserGroups(r, session.Groups)
		}

		next.ServeHTTP(w, r)
	})
}

// sessionPostAuthMiddleware runs after authentication. If authentication just
// occurred (i.e., user is in context but not from an existing session), it
// regenerates the session to prevent fixation. It also caches group memberships.
func sessionPostAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("AUTHN/Z: [%s] Entering post-auth middleware.", r.RemoteAddr)
		// Check if a user was authenticated in this request cycle by the SSPI handler.
		// We know this if a user exists in the context, but the context wasn't flagged
		// by the sessionMiddleware.
		if username, ok := gwim.User(r); ok {
			log.Printf("AUTHN/Z: [%s] User '%s' present in context.", r.RemoteAddr, username)
			if authFromSession, _ := r.Context().Value(sessionAuthKey).(bool); !authFromSession {
				// This was a new login, not a request with an existing session.
				// Regenerate the session to prevent fixation attacks.
				log.Printf("AUTHN/Z: [%s] New login detected for user '%s'. Regenerating session.", r.RemoteAddr, username)
				regenerateSession(w, r, username)
			}
		}

		// Now, handle group caching.
		// This happens after the LdapGroupProvider has run.
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			if session, ok := getSession(cookie.Value); ok {
				// If the session doesn't have groups or they are expired, check the context.
				if session.Groups == nil || time.Now().After(session.GroupsExpiry) {
					log.Printf("AUTHN/Z: [%s] Checking for groups to cache for user '%s' in session %s.", r.RemoteAddr, session.Username, cookie.Value)
					if groups, ok := gwim.UserGroups(r); ok {
						log.Printf("AUTHN/Z: [%s] Found groups in context for user '%s'. Caching them.", r.RemoteAddr, session.Username)
						updateSessionWithGroups(cookie.Value, groups)
					}
				}
			}
		}

		next.ServeHTTP(w, r)
		log.Printf("AUTHN/Z: [%s] Exiting post-auth middleware.", r.RemoteAddr)
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
	log.Println("AUTHN/Z: Configuring middleware chain...")

	// Post-Auth Session Creator: If SSPI just ran, this creates the session.
	handler = sessionPostAuthMiddleware(handler)
	log.Println("AUTHN/Z: --> Applied post-auth session middleware (runs last)")

	// LDAP Group Provider: Enriches context with group info (runs after auth).
	if *ldapAddress != "" {
		handler = gwim.NewLdapGroupProvider(handler, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN)
		log.Println("AUTHN/Z: --> Applied LDAP group provider")
	}

	// SSPI Handler: Performs Kerberos/NTLM auth if no user is in the context.
	handler, err := gwim.NewSSPIHandler(handler, useNTLM)
	if err != nil {
		log.Fatalf("Failed to create SSPI handler: %v", err)
	}
	log.Println("AUTHN/Z: --> Applied SSPI handler (Kerberos/NTLM)")

	// Session Middleware: The first handler to run. Checks for an existing session.
	handler = sessionMiddleware(handler)
	log.Println("AUTHN/Z: --> Applied session middleware (runs first)")

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
		log.Printf("AUTHN/Z: [%s] Unauthorized access to root handler without user in context.", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	groups, _ := gwim.UserGroups(r)
	log.Printf("AUTHN/Z: [%s] Root handler reached for user '%s' with groups: %v", r.RemoteAddr, username, groups)
	if len(groups) > 0 {
		fmt.Fprintf(w, "Hello, %s! Your LDAP groups are: %v", username, groups)
	} else {
		fmt.Fprintf(w, "Hello, %s! You have a valid session.", username)
	}
}
