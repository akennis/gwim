// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package gwim

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/akennis/gwim/auth"
	"github.com/akennis/gwim/cert"
	"github.com/alexbrainman/sspi"
)

// Exported keys for context access
const (
	ContextKeyConnID = auth.ContextKeyConnID
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
	username = auth.NormalizeUsername(username)
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
func NewSSPIHandler(next http.Handler, useNTLM bool, options ...auth.AuthErrorHandlers) (http.Handler, error) {
	serverCreds, err := sspi.AcquireCredentials("", "Negotiate", sspi.SECPKG_CRED_INBOUND, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire credentials for SPNEGO: %w", err)
	}

	var handler http.Handler
	if useNTLM {
		handler = auth.NtlmAuthn(serverCreds, options...)(next)
	} else {
		handler = auth.KerberosAuthn(serverCreds, options...)(next)
	}

	return handler, nil
}

// CertStore identifies which Windows certificate store to search.
// Use CertStoreLocalMachine or CertStoreCurrentUser.
type CertStore = cert.CertStore

const (
	// CertStoreLocalMachine searches the LocalMachine certificate store (default).
	CertStoreLocalMachine CertStore = cert.StoreLocalMachine
	// CertStoreCurrentUser searches the CurrentUser certificate store.
	CertStoreCurrentUser CertStore = cert.StoreCurrentUser
)

// GetCertificate retrieves a TLS certificate from the Windows certificate store
// by Common Name. The certificate is validated (expiry, EKU, chain) before
// being returned. The returned CertificateSource must be closed on server
// shutdown to release Windows store handles.
//
// For zero-downtime certificate rotation, use GetCertificateFunc instead.
func GetCertificate(certSubject string, store CertStore) (*cert.CertificateSource, error) {
	return cert.GetWin32Cert(certSubject, store)
}

// GetCertificateFunc returns a tls.Config.GetCertificate callback that fetches
// the named certificate from the Windows store with caching and automatic
// refresh when the certificate is within 7 days of expiry. Use this instead of
// GetCertificate to enable zero-downtime certificate rotation.
func GetCertificateFunc(certSubject string, store CertStore) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cert.GetCertificateFunc(certSubject, store)
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
func NewLdapGroupProvider(next http.Handler, ldapAddress, ldapUsersDN, ldapServiceAccountSPN string, options ...auth.AuthErrorHandlers) http.Handler {
	ldapServerInfo := auth.LdapServerInfo{
		Address:           ldapAddress,
		UsersDN:           ldapUsersDN,
		ServiceAccountSPN: ldapServiceAccountSPN,
	}
	return auth.LdapGroupProvider(ldapServerInfo, options...)(next)
}
