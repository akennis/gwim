// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package gwim

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"

	iauth "github.com/akennis/gwim/internal/auth"
	icert "github.com/akennis/gwim/internal/cert"
	"github.com/alexbrainman/sspi"
)

// --- Re-exported types ---
//
// These type aliases are the only way callers should interact with the types
// defined in the internal packages. Importing github.com/akennis/gwim is the
// only import required to use this library.

// AuthErrorHandler is a function type for handling an authentication or
// authorisation error. Assign one to any field of AuthErrorHandlers to
// override the default behaviour for that specific error category.
type AuthErrorHandler = iauth.AuthErrorHandler

// AuthErrorHandlers configures the error-handling behaviour of the
// authentication middleware. Pass one as a variadic option to NewSSPIHandler
// or NewLdapGroupProvider. Any field left nil falls back to the built-in
// default for that category; set OnGeneralError as a single catch-all.
type AuthErrorHandlers = iauth.AuthErrorHandlers

// --- Context helpers ---

// User returns the authenticated username from the request context.
// The second return value is false if no user has been set.
func User(r *http.Request) (string, bool) {
	username, ok := r.Context().Value(iauth.ContextKeyUsername).(string)
	if !ok || username == "" {
		return "", false
	}
	return username, true
}

// SetUser injects a username into the request context, normalising it first.
// Use this to resume a session without re-running SSPI authentication.
func SetUser(r *http.Request, username string) *http.Request {
	username = iauth.NormalizeUsername(username)
	ctx := context.WithValue(r.Context(), iauth.ContextKeyUsername, username)
	return r.WithContext(ctx)
}

// UserGroups returns the authenticated user's group memberships from the
// request context. The second return value is false if no groups are present.
func UserGroups(r *http.Request) ([]string, bool) {
	groups, ok := r.Context().Value(iauth.ContextKeyUserGroups).([]string)
	if !ok {
		return nil, false
	}
	return groups, true
}

// SetUserGroups injects group memberships into the request context.
// Use this to resume a session with cached groups without re-running LDAP.
func SetUserGroups(r *http.Request, groups []string) *http.Request {
	ctx := context.WithValue(r.Context(), iauth.ContextKeyUserGroups, groups)
	return r.WithContext(ctx)
}

// --- Middleware constructors ---

// NewSSPIHandler returns an http.Handler that authenticates each request
// using Kerberos (useNTLM=false) or NTLM (useNTLM=true) via Windows SSPI,
// then delegates to next. Pass an AuthErrorHandlers value to customise error
// responses; any unset fields fall back to sensible defaults.
func NewSSPIHandler(next http.Handler, useNTLM bool, options ...AuthErrorHandlers) (http.Handler, error) {
	serverCreds, err := sspi.AcquireCredentials("", "Negotiate", sspi.SECPKG_CRED_INBOUND, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire credentials for SPNEGO: %w", err)
	}

	var handler http.Handler
	if useNTLM {
		handler = iauth.NtlmAuthn(serverCreds, options...)(next)
	} else {
		handler = iauth.KerberosAuthn(serverCreds, options...)(next)
	}

	return handler, nil
}

// NewLdapGroupProvider returns an http.Handler that looks up the authenticated
// user's Active Directory group memberships via LDAP and stores them in the
// request context, then delegates to next.
func NewLdapGroupProvider(next http.Handler, ldapAddress, ldapUsersDN, ldapServiceAccountSPN string, options ...AuthErrorHandlers) http.Handler {
	ldapServerInfo := iauth.LdapServerInfo{
		Address:           ldapAddress,
		UsersDN:           ldapUsersDN,
		ServiceAccountSPN: ldapServiceAccountSPN,
	}
	return iauth.LdapGroupProvider(ldapServerInfo, options...)(next)
}

// --- TLS certificate helpers ---

// CertStore identifies which Windows certificate store to search.
// Use CertStoreLocalMachine or CertStoreCurrentUser.
type CertStore = icert.CertStore

const (
	// CertStoreLocalMachine searches the LocalMachine certificate store (default).
	CertStoreLocalMachine CertStore = icert.StoreLocalMachine
	// CertStoreCurrentUser searches the CurrentUser certificate store.
	CertStoreCurrentUser CertStore = icert.StoreCurrentUser
)

// GetCertificateFunc fetches the named certificate from the Windows store
// immediately — surfacing any configuration error at startup rather than on
// the first TLS handshake — and returns a tls.Config.GetCertificate callback
// that transparently refreshes the certificate when it is within 7 days of
// expiry, enabling zero-downtime rotation.
//
// The returned io.Closer releases the Windows store handles for the
// currently-cached certificate. Call it after http.Server.Shutdown returns
// to ensure all active connections have already finished.
func GetCertificateFunc(certSubject string, store CertStore) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error) {
	return icert.GetCertificateFunc(certSubject, store)
}

// --- Server configuration ---

// ConfigureNTLM sets the ConnContext on server so that each connection is
// assigned a unique ID. This ID is required by the NTLM handler to correlate
// the two-round token exchange across separate HTTP requests on the same
// keep-alive connection.
func ConfigureNTLM(server *http.Server) {
	connID := uint64(0)
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, iauth.ContextKeyConnID, atomic.AddUint64(&connID, 1))
	}
}
