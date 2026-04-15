// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akennis/gwim"
	"github.com/patrickmn/go-cache"
)

// --- Session Management ---

// ctxKey is an unexported type for context keys set by this file, preventing
// collisions with keys from other packages.
type ctxKey string

const sessionAuthKey ctxKey = "session-authenticated"

type Session struct {
	Username     string
	Groups       []string
	GroupsExpiry time.Time
	ClientIP     string // IP address the session was created from; used to reject stolen cookies.
}

var (
	sessionTTL   = 15 * time.Minute
	sessionStore = cache.New(sessionTTL, 2*sessionTTL)
)

const sessionCookieName = "__Host-sec-win-server-session"

// clientIP extracts the IP address (without port) from r.RemoteAddr.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// newSession creates a new session for the given username bound to the client's
// IP address and returns the session ID. Subsequent requests presenting this
// session cookie from a different IP will be rejected.
func newSession(username, ip string) string {
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		log.Fatalf("failed to generate session ID: %v", err)
	}
	id := hex.EncodeToString(sessionID)
	sessionStore.Set(id, Session{Username: username, ClientIP: ip}, cache.DefaultExpiration)
	log.Printf("Created session %s for user %s bound to IP %s", id, username, ip)
	return id
}

// getSession returns the session from the session store if the session is valid.
func getSession(sessionID string) (Session, bool) {
	item, found := sessionStore.Get(sessionID)
	if !found {
		return Session{}, false
	}
	return item.(Session), true
}

// regenerateSession clears the old session and creates a new one for the user. It returns the new session ID.
func regenerateSession(w http.ResponseWriter, r *http.Request, username string) string {
	// If a cookie exists, delete the old session it points to.
	if oldCookie, err := r.Cookie(sessionCookieName); err == nil {
		sessionStore.Delete(oldCookie.Value)
		log.Printf("Regenerating session: Deleted old session %s", oldCookie.Value)
	}

	// Create a new session bound to the client's IP.
	sessionID := newSession(username, clientIP(r))

	// Set the new session cookie.
	newCookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(sessionTTL),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, newCookie)

	// Replace the cookie on the request so subsequent middleware sees the new session.
	// This is necessary because r.AddCookie appends, and r.Cookie may return the old
	// stale cookie if it appears first in the header.
	var cookies []*http.Cookie
	for _, c := range r.Cookies() {
		if c.Name != sessionCookieName {
			cookies = append(cookies, c)
		}
	}
	cookies = append(cookies, newCookie)

	// Clear the existing Cookie header and rebuild it.
	r.Header.Del("Cookie")
	for _, c := range cookies {
		r.AddCookie(c)
	}

	log.Printf("Regenerated session: New session is %s for user %s", sessionID, username)
	return sessionID
}

// updateSessionWithGroups updates the session store with the user's group memberships.
func updateSessionWithGroups(sessionID string, groups []string) {
	item, expiry, found := sessionStore.GetWithExpiration(sessionID)
	if !found {
		return
	}
	session := item.(Session)
	session.Groups = groups
	session.GroupsExpiry = time.Now().Add(5 * time.Minute)
	sessionStore.Set(sessionID, session, time.Until(expiry))
	log.Printf("Cached groups for user %s in session %s", session.Username, sessionID)
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
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1})
			next.ServeHTTP(w, r)
			return
		}

		// Reject the session if the client IP has changed. This prevents a
		// stolen cookie from being replayed from a different machine.
		if reqIP := clientIP(r); session.ClientIP != "" && reqIP != session.ClientIP {
			log.Printf("AUTHN/Z: [%s] Session IP mismatch for user '%s' (expected %s, got %s). Invalidating session.", r.RemoteAddr, session.Username, session.ClientIP, reqIP)
			sessionStore.Delete(cookie.Value)
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1})
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
	certFromCurrentUser := flag.Bool("cert-from-current-user", false, "Whether to pull the certificate from the CurrentUser store instead of LocalMachine")
	useNTLM := flag.Bool("use-ntlm", false, "Use NTLM instead of Kerberos for authentication (required for non-domain or localhost scenarios)")
	ldapAddress := flag.String("ldap-address", "", "The address of the LDAP server")
	ldapUsersDN := flag.String("ldap-users-dn", "", "The DN for users in the LDAP server")
	ldapServiceAccountSPN := flag.String("ldap-service-account-spn", "", "The SPN for the service account in the LDAP server")
	flag.Parse()

	if err := runServer(*serverAddr, *certSubject, *certFromCurrentUser, *useNTLM, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN); err != nil {
		log.Fatal(err)
	}
}

func runServer(serverAddr, certSubject string, certFromCurrentUser, useNTLM bool, ldapAddress, ldapUsersDN, ldapServiceAccountSPN string) error {
	if ldapAddress == "" || ldapUsersDN == "" || ldapServiceAccountSPN == "" {
		log.Println("Warning: LDAP flags not set, group provider will be disabled.")
	}

	// Initialize router
	router := http.NewServeMux()
	router.HandleFunc("/", secRootHandler)

	// --- Apply Middleware (in reverse order of actual execution) ---
	var handler http.Handler = router
	log.Println("AUTHN/Z: Configuring middleware chain...")

	// Post-Auth Session Creator: If SSPI just ran, this creates the session.
	handler = sessionPostAuthMiddleware(handler)
	log.Println("AUTHN/Z: --> Applied post-auth session middleware (runs last)")

	// LDAP Group Provider: Enriches context with group info (runs after auth).
	if ldapAddress != "" {
		ldapProvider, err := gwim.NewLDAPProvider(
			gwim.WithLDAPAddress(ldapAddress),
			gwim.WithLDAPUsersDN(ldapUsersDN),
			gwim.WithLDAPServiceAccountSPN(ldapServiceAccountSPN),
			gwim.WithLDAPErrorHandlers(gwim.AuthErrorHandlers{OnGeneralError: onSecAuthError}),
		)
		if err != nil {
			return fmt.Errorf("failed to create LDAP provider: %w", err)
		}
		handler = ldapProvider.Middleware(handler)
		log.Println("AUTHN/Z: --> Applied LDAP group provider")
	}

	// SSPI Provider: Performs Kerberos/NTLM auth if no user is in the context.
	var sspiOpts []gwim.SSPIOption
	if useNTLM {
		sspiOpts = append(sspiOpts, gwim.WithNTLM())
	}
	sspiOpts = append(sspiOpts, gwim.WithSSPIErrorHandlers(gwim.AuthErrorHandlers{OnGeneralError: onSecAuthError}))
	sspiProvider, err := gwim.NewSSPIProvider(sspiOpts...)
	if err != nil {
		return fmt.Errorf("failed to create SSPI provider: %w", err)
	}
	handler = sspiProvider.Middleware(handler)
	log.Println("AUTHN/Z: --> Applied SSPI handler (Kerberos/NTLM)")

	// Session Middleware: The first handler to run. Checks for an existing session.
	handler = sessionMiddleware(handler)
	log.Println("AUTHN/Z: --> Applied session middleware (runs first)")

	certStore := gwim.CertStoreLocalMachine
	if certFromCurrentUser {
		certStore = gwim.CertStoreCurrentUser
	}

	// GetCertificateFunc fetches the cert from the Windows store immediately so
	// that any configuration error (wrong subject, expired cert, etc.) is caught
	// here at startup rather than on the first TLS handshake. The returned
	// callback caches the cert and automatically refreshes it in the background
	// within the refresh window before expiry.
	// The closer releases Windows store handles after all connections have drained.
	getCertificate, certCloser, err := gwim.GetCertificateFunc(certSubject, certStore, gwim.DefaultRefreshThreshold, gwim.DefaultRetryInterval)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate %q: %w", certSubject, err)
	}
	defer func() {
		if err := certCloser.Close(); err != nil {
			log.Printf("Failed to close certificate store: %v", err)
		}
		log.Printf("Certificate store closed.")
	}()

	// Configure HTTPS server.
	srv := &http.Server{
		Addr:    serverAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			GetCertificate: getCertificate,
			MinVersion:     tls.VersionTLS13,
		},
	}

	if useNTLM {
		gwim.ConfigureNTLM(srv)
	}

	// --- Graceful Shutdown ---
	// Create a context that is canceled on receiving an interrupt signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run the server in a goroutine so that it doesn't block the shutdown handling.
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Starting secure server on https://%s", srv.Addr)
		//ListenAndServeTLS always returns a non-nil error.
		serverErrors <- srv.ListenAndServeTLS("", "")
	}()

	// Wait for a shutdown signal or a server error.
	select {
	case err := <-serverErrors:
		// The server failed to start or crashed.
		// The deferred certCloser.Close() will run when we return.
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		// A shutdown signal was received.
		log.Println("Shutting down server...")

		// Give the server a deadline to gracefully close connections.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var shutdownErr error
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Server shutdown error: %v", err)
			shutdownErr = fmt.Errorf("server shutdown: %w", err)
		}

		// Wait for the ListenAndServeTLS goroutine to exit.
		if shutdownRes := <-serverErrors; shutdownRes != http.ErrServerClosed {
			log.Printf("Server shutdown error: %v", shutdownRes)
			if shutdownErr == nil {
				shutdownErr = fmt.Errorf("server shutdown: %w", shutdownRes)
			}
		} else {
			log.Println("Server has shut down gracefully.")
		}

		return shutdownErr
	}
}

func onSecAuthError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("AUTHN/Z: [%s] Authentication failed: %v", r.RemoteAddr, err)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	data := struct {
		Error string
	}{
		Error: err.Error(),
	}
	if templateErr := secErrorTemplate.Execute(w, data); templateErr != nil {
		log.Printf("ERROR: failed to execute error handler template: %v", templateErr)
	}
}

var secErrorTemplate = template.Must(template.New("error").Parse(`
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

var secRootTemplate = template.Must(template.New("root").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>GWIM Welcome</title>
</head>
<body>
    <h1>Hello, {{.Username}}!</h1>
    {{if .Groups}}
        <p>You have a valid session and belong to the following LDAP groups:</p>
        <ul>
            {{range .Groups}}
                <li>{{.}}</li>
            {{end}}
        </ul>
    {{else}}
        <p>You have a valid session.</p>
    {{end}}
</body>
</html>
`))

type secRootData struct {
	Username string
	Groups   []string
}

func secRootHandler(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := secRootData{
		Username: username,
		Groups:   groups,
	}
	err := secRootTemplate.Execute(w, data)
	if err != nil {
		log.Printf("ERROR: failed to execute root handler template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
