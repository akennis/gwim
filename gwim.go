package gwim

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/akennis/gwim/auth"
	"github.com/akennis/gwim/cert"
	"github.com/alexbrainman/sspi"
)

// User returns the username from the request context.
// The second return value is true if the user was found in the context.
func User(r *http.Request) (string, bool) {
	username, ok := r.Context().Value(auth.ContextKeyUsername).(string)
	if !ok || username == "" {
		return "", false
	}
	return username, true
}

// SetUser adds the username to the request context and returns the modified request.
// This allows an application to manage sessions itself and inject the user's
// identity into the context, bypassing the need for per-request authentication.
func SetUser(r *http.Request, username string) *http.Request {
	username = strings.ToLower(strings.Split(username, "@")[0])
	ctx := context.WithValue(r.Context(), auth.ContextKeyUsername, username)
	return r.WithContext(ctx)
}

// UserGroups returns the user's groups from the request context.
// The second return value is true if the groups were found in the context.
func UserGroups(r *http.Request) ([]string, bool) {
	groups, ok := r.Context().Value(auth.ContextKeyUserGroups).([]string)
	if !ok {
		return nil, false
	}
	return groups, true
}

// SetUserGroups adds the user's group memberships to the request context and
// returns the modified request. This allows an application to manage group
// caching itself and inject the groups into the context, bypassing the need for
// the LdapGroupProvider to perform a query.
func SetUserGroups(r *http.Request, groups []string) *http.Request {
	ctx := context.WithValue(r.Context(), auth.ContextKeyUserGroups, groups)
	return r.WithContext(ctx)
}

// NewSSPIHandler returns a new http.Handler that authenticates requests
// using Kerberos or NTLM, and then calls the next handler in the chain.
// The useNTLM boolean determines which authentication method to use.
// If useNTLM is true, NTLM is used. Otherwise, Kerberos is used.
func NewSSPIHandler(next http.Handler, useNTLM bool) (http.Handler, error) {
	serverCreds, err := sspi.AcquireCredentials("", "Negotiate", sspi.SECPKG_CRED_INBOUND, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire credentials for SPNEGO: %w", err)
	}

	var handler http.Handler
	if useNTLM {
		handler = auth.NtlmAuthn(serverCreds)(next)
	} else {
		handler = auth.KerberosAuthn(serverCreds)(next)
	}

	return handler, nil
}

// ConfigureTLS configures the http.Server with a TLS certificate from the
// Windows certificate store. The certSubject is the subject of the
// certificate to use.
func ConfigureTLS(server *http.Server, certSubject string) error {
	certificate, err := cert.GetWin32Cert(certSubject)
	if err != nil {
		return fmt.Errorf("error loading certificate from Windows store: %w", err)
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	}

	return nil
}

// ConfigureNTLM configures the http.Server with the ConnContext required for NTLM.
func ConfigureNTLM(server *http.Server) {
	connID := uint64(0)
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, auth.ContextKeyConnID, atomic.AddUint64(&connID, 1))
	}
}

// NewLdapGroupProvider returns a new http.Handler that enriches the request context
// with the user's LDAP groups.
func NewLdapGroupProvider(next http.Handler, ldapAddress, ldapUsersDN, ldapServiceAccountSPN string) http.Handler {
	ldapServerInfo := auth.LdapServerInfo{
		Address:           ldapAddress,
		UsersDN:           ldapUsersDN,
		ServiceAccountSPN: ldapServiceAccountSPN,
	}
	return auth.LdapGroupProvider(ldapServerInfo)(next)
}
