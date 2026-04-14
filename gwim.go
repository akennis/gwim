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
	"time"

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
// authentication middleware. Pass one to WithSSPIErrorHandlers or
// WithLDAPErrorHandlers. Any field left nil falls back to the built-in
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

// --- SSPI Provider ---

type sspiConfig struct {
	useNTLM     bool
	errHandlers AuthErrorHandlers
}

// SSPIOption configures an SSPIProvider.
type SSPIOption func(*sspiConfig)

// WithNTLM configures the SSPIProvider to use NTLM instead of Kerberos.
// Required for non-domain or localhost scenarios.
func WithNTLM() SSPIOption {
	return func(c *sspiConfig) {
		c.useNTLM = true
	}
}

// WithSSPIErrorHandlers overrides the default error-handling behaviour of the
// SSPI middleware. Any field left nil falls back to the built-in default.
func WithSSPIErrorHandlers(h AuthErrorHandlers) SSPIOption {
	return func(c *sspiConfig) {
		c.errHandlers = h
	}
}

// SSPIProvider authenticates requests using Windows SSPI (Kerberos or NTLM).
// Create one with NewSSPIProvider, then register its Middleware method with
// your router's Use() method or wrap handlers manually.
type SSPIProvider struct {
	useNTLM    bool
	middleware func(http.Handler) http.Handler
}

// NewSSPIProvider acquires the required Windows SSPI credentials and returns
// a provider whose Middleware method satisfies func(http.Handler) http.Handler.
// Credential acquisition happens once here so that any configuration error is
// surfaced at startup rather than on the first request.
func NewSSPIProvider(opts ...SSPIOption) (*SSPIProvider, error) {
	cfg := &sspiConfig{}
	for _, o := range opts {
		o(cfg)
	}

	serverCreds, err := sspi.AcquireCredentials("", "Negotiate", sspi.SECPKG_CRED_INBOUND, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire credentials for SPNEGO: %w", err)
	}

	var mw func(http.Handler) http.Handler
	if cfg.useNTLM {
		mw = iauth.NtlmAuthn(serverCreds, cfg.errHandlers)
	} else {
		mw = iauth.KerberosAuthn(serverCreds, cfg.errHandlers)
	}

	return &SSPIProvider{useNTLM: cfg.useNTLM, middleware: mw}, nil
}

// Middleware satisfies func(http.Handler) http.Handler and can be passed
// directly to any router's Use() method or used to wrap a handler manually:
//
//	router.Use(sspiProvider.Middleware)
//	handler := sspiProvider.Middleware(myHandler)
func (p *SSPIProvider) Middleware(next http.Handler) http.Handler {
	return p.middleware(next)
}

// --- LDAP Provider ---

type ldapConfig struct {
	address     string
	usersDN     string
	spn         string
	timeout     time.Duration
	ttl         time.Duration
	errHandlers AuthErrorHandlers
}

// LDAPOption configures an LDAPProvider.
type LDAPOption func(*ldapConfig)

// WithLDAPAddress sets the address of the LDAP server (host:port).
func WithLDAPAddress(addr string) LDAPOption {
	return func(c *ldapConfig) {
		c.address = addr
	}
}

// WithLDAPUsersDN sets the Distinguished Name under which users are searched.
func WithLDAPUsersDN(dn string) LDAPOption {
	return func(c *ldapConfig) {
		c.usersDN = dn
	}
}

// WithLDAPServiceAccountSPN sets the Service Principal Name of the account
// used to bind to the LDAP server via GSSAPI/Kerberos.
func WithLDAPServiceAccountSPN(spn string) LDAPOption {
	return func(c *ldapConfig) {
		c.spn = spn
	}
}

// WithLDAPTimeout sets the per-operation timeout applied to every LDAP call
// on each connection (searches, health-check probes, etc.).
// Zero is treated as DefaultLdapTimeout.
func WithLDAPTimeout(d time.Duration) LDAPOption {
	return func(c *ldapConfig) {
		c.timeout = d
	}
}

// WithLDAPConnectionTTL sets the maximum lifetime of a pooled LDAP connection.
// This prevents stale Kerberos tickets from causing failures on long-lived
// connections. Zero disables the TTL.
func WithLDAPConnectionTTL(d time.Duration) LDAPOption {
	return func(c *ldapConfig) {
		c.ttl = d
	}
}

// WithLDAPErrorHandlers overrides the default error-handling behaviour of the
// LDAP middleware. Any field left nil falls back to the built-in default.
func WithLDAPErrorHandlers(h AuthErrorHandlers) LDAPOption {
	return func(c *ldapConfig) {
		c.errHandlers = h
	}
}

// LDAPProvider enriches an authenticated request's context with the user's
// Active Directory group memberships. Create one with NewLDAPProvider, then
// register its Middleware method with your router or wrap handlers manually.
// It must be placed after SSPIProvider in the middleware chain.
type LDAPProvider struct {
	middleware func(http.Handler) http.Handler
}

// NewLDAPProvider returns an LDAPProvider configured by the given options.
// LDAP connections are established lazily per request, so no I/O occurs here.
func NewLDAPProvider(opts ...LDAPOption) *LDAPProvider {
	cfg := &ldapConfig{
		timeout: DefaultLdapTimeout,
		ttl:     DefaultLdapTTL,
	}
	for _, o := range opts {
		o(cfg)
	}

	// Enforce a minimum timeout to prevent indefinite hangs against
	// misbehaving domain controllers.
	const minLdapTimeout = 30 * time.Second
	if cfg.timeout < minLdapTimeout {
		cfg.timeout = minLdapTimeout
	}

	ldapServerInfo := iauth.LdapServerInfo{
		Address:           cfg.address,
		UsersDN:           cfg.usersDN,
		ServiceAccountSPN: cfg.spn,
		Timeout:           cfg.timeout,
		ConnectionTTL:     cfg.ttl,
	}
	return &LDAPProvider{middleware: iauth.LdapGroupProvider(ldapServerInfo, cfg.errHandlers)}
}

// Middleware satisfies func(http.Handler) http.Handler and can be passed
// directly to any router's Use() method or used to wrap a handler manually:
//
//	router.Use(ldapProvider.Middleware)
//	handler := ldapProvider.Middleware(myHandler)
func (p *LDAPProvider) Middleware(next http.Handler) http.Handler {
	return p.middleware(next)
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

	// DefaultRefreshThreshold is the window before certificate expiry at which
	// GetCertificateFunc triggers a background refresh. Pass this value to
	// GetCertificateFunc when you do not need a custom refresh window.
	DefaultRefreshThreshold = 7 * 24 * time.Hour

	// DefaultRetryInterval is the minimum time between background refresh
	// attempts. If a refresh fails (e.g. the renewed certificate is not yet in
	// the store), subsequent requests within the refresh window are served from
	// the cache without spawning new goroutines until this interval elapses.
	DefaultRetryInterval = 5 * time.Minute

	// DefaultLdapTimeout is the per-operation timeout applied to every LDAP
	// call (searches, health-check probes, etc.). In a corporate Active
	// Directory environment LDAP round-trips are typically sub-100 ms; five
	// seconds is generous while still failing fast against a hung server.
	DefaultLdapTimeout = 5 * time.Second

	// DefaultLdapTTL is the default maximum lifetime for a pooled LDAP connection.
	// In Active Directory, Kerberos tickets typically expire after 10 hours.
	// Rotating connections every 1 hour ensures they never encounter an expired ticket.
	DefaultLdapTTL = 1 * time.Hour
)

// GetCertificateFunc fetches the named certificate from the Windows store
// immediately — surfacing any configuration error at startup rather than on
// the first TLS handshake — and returns a tls.Config.GetCertificate callback
// that transparently refreshes the certificate in a background goroutine when
// it is within refreshThreshold of expiry, enabling zero-downtime rotation.
// Pass DefaultRefreshThreshold for the standard 7-day window.
//
// retryInterval is the minimum time between background refresh attempts. If
// the store is temporarily unavailable (e.g. the renewed certificate has not
// been deployed yet), requests that arrive within the refresh window would
// otherwise each spawn a new goroutine. retryInterval rate-limits that
// behaviour so that at most one attempt runs per interval.
// Pass DefaultRetryInterval for the standard 5-minute window.
//
// The returned io.Closer releases the Windows store handles for the
// currently-cached certificate. Call it after http.Server.Shutdown returns
// to ensure all active connections have already finished.
func GetCertificateFunc(certSubject string, store CertStore, refreshThreshold, retryInterval time.Duration) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error) {
	return icert.GetCertificateFunc(certSubject, store, refreshThreshold, retryInterval)
}

// CertificateSource holds a TLS certificate retrieved from the Windows store.
// Call Close when the certificate is no longer needed (e.g. on server shutdown).
type CertificateSource = icert.CertificateSource

// GetWin32Cert retrieves a certificate from the Windows certificate store by
// Common Name and returns a CertificateSource. The certificate is validated
// before being returned: it must not be expired and must carry the
// ExtKeyUsageServerAuth extended key usage.
//
// The caller must call Close on the returned CertificateSource when it is no
// longer needed to release Windows store handles.
//
// For servers that need zero-downtime certificate rotation, use
// GetCertificateFunc instead.
func GetWin32Cert(subject string, store CertStore) (*CertificateSource, error) {
	return icert.GetWin32Cert(subject, store)
}

// --- Server configuration ---

// ConfigureNTLM sets the ConnContext on server so that each connection is
// assigned a unique ID. This ID is required by the NTLM handler to correlate
// the two-round token exchange across separate HTTP requests on the same
// keep-alive connection. Only required when using NTLM authentication.
func ConfigureNTLM(server *http.Server) {
	connID := uint64(0)
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, iauth.ContextKeyConnID, atomic.AddUint64(&connID, 1))
	}
}
