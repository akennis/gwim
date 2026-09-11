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
// An empty username is stored as-is; User(r) will return ("", false) for it
// since empty strings are treated as "no authenticated user."
func SetUser(r *http.Request, username string) *http.Request {
	username = iauth.NormalizeUsername(username)
	ctx := context.WithValue(r.Context(), iauth.ContextKeyUsername, username)
	return r.WithContext(ctx)
}

// UserGroups returns the authenticated user's group memberships from the
// request context. The second return value is false if no groups are present.
// After the LDAP middleware runs, it returns ([]string{}, true) for users
// with no group memberships, distinguishing "no groups" from "LDAP didn't run."
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
	creds      *sspi.Credentials
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

	return &SSPIProvider{creds: serverCreds, useNTLM: cfg.useNTLM, middleware: mw}, nil
}

// Close releases the Windows SSPI credentials held by this provider.
// Call this on server shutdown.
func (p *SSPIProvider) Close() error {
	if p.creds == nil {
		return nil
	}
	return p.creds.Release()
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

// Sentinel errors returned by LDAPProvider.Groups. Compare with errors.Is
// rather than by message; the underlying directory error is wrapped alongside
// and remains reachable through errors.Unwrap.
var (
	// ErrLDAPConnection reports that the directory could not be reached or the
	// service-account bind failed. The user's group membership is unknown.
	ErrLDAPConnection = iauth.ErrLDAPConnection

	// ErrLDAPLookup reports that the directory was reachable but the search
	// itself failed. The user's group membership is unknown.
	ErrLDAPLookup = iauth.ErrLDAPLookup

	// ErrUserNotFound reports that the directory answered and the account does
	// not exist, is disabled, or matched more than one entry. This is a
	// definitive answer rather than an outage, so it warrants a clean deny and
	// not a server error. It wraps ErrLDAPLookup.
	ErrUserNotFound = iauth.ErrUserNotFound
)

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
	lookup *iauth.GroupLookup
}

// Close drains the LDAP connection pool, closing all idle connections.
// Call this on server shutdown after the HTTP server has stopped accepting
// new requests.
func (p *LDAPProvider) Close() error {
	return p.lookup.Close()
}

// NewLDAPProvider returns an LDAPProvider configured by the given options.
// LDAP connections are established lazily per request after initial validation.
func NewLDAPProvider(opts ...LDAPOption) (*LDAPProvider, error) {
	cfg := &ldapConfig{
		timeout: DefaultLdapTimeout,
		ttl:     DefaultLdapTTL,
	}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.address == "" {
		return nil, fmt.Errorf("gwim: LDAP address is required (use WithLDAPAddress)")
	}
	if cfg.usersDN == "" {
		return nil, fmt.Errorf("gwim: LDAP users DN is required (use WithLDAPUsersDN)")
	}
	if cfg.spn == "" {
		return nil, fmt.Errorf("gwim: LDAP service account SPN is required (use WithLDAPServiceAccountSPN)")
	}

	ldapServerInfo := iauth.LdapServerInfo{
		Address:           cfg.address,
		UsersDN:           cfg.usersDN,
		ServiceAccountSPN: cfg.spn,
		Timeout:           cfg.timeout,
		ConnectionTTL:     cfg.ttl,
	}

	if err := iauth.ValidateLDAP(ldapServerInfo); err != nil {
		return nil, fmt.Errorf("failed to validate LDAP configuration: %w", err)
	}

	return &LDAPProvider{lookup: iauth.NewGroupLookup(ldapServerInfo, cfg.errHandlers)}, nil
}

// Middleware satisfies func(http.Handler) http.Handler and can be passed
// directly to any router's Use() method or used to wrap a handler manually:
//
//	router.Use(ldapProvider.Middleware)
//	handler := ldapProvider.Middleware(myHandler)
func (p *LDAPProvider) Middleware(next http.Handler) http.Handler {
	return p.lookup.Middleware(next)
}

// Groups returns the Active Directory group memberships of username as
// distinguished names, using the same pooled connections and service-account
// bind as Middleware. It is the lookup Middleware performs, made available to
// callers that have no request in hand — re-checking membership on a timer for
// a username recovered from a token, for example. username is normalized the
// same way the authentication middleware normalizes it (stripping a DOMAIN\
// prefix or @REALM suffix and lowercasing), so a token-derived username works
// the same here as it does through Middleware.
//
// A failure wraps one of ErrLDAPConnection, ErrLDAPLookup, or ErrUserNotFound;
// classify with errors.Is. The distinction matters: the first two mean the
// membership is unknown and the caller must decide whether to fail closed,
// while ErrUserNotFound is a definitive answer about a deleted, disabled, or
// ambiguous account.
//
// ctx bounds how long Groups waits, not the search itself. The underlying LDAP
// client applies its timeout per connection, so an in-flight search cannot be
// interrupted: when ctx is done first, Groups returns ctx.Err() promptly and
// the search runs to completion in the background, bounded by WithLDAPTimeout,
// after which its connection returns to the pool. The effective wait is
// min(ctx deadline, WithLDAPTimeout). The background lookup still checks ctx
// before starting any new expensive work of its own — dialing a replacement
// connection, or issuing another batch of group searches — so a burst of
// abandoned calls does not pile unbounded connections onto the directory.
func (p *LDAPProvider) Groups(ctx context.Context, username string) ([]string, error) {
	return p.lookup.Groups(ctx, username)
}

// --- Outbound authentication transports ---

type clientTransportConfig struct {
	base         http.RoundTripper
	ntlmFallback bool
}

// ClientTransportOption configures an outbound authentication transport.
type ClientTransportOption func(*clientTransportConfig)

// WithClientBaseTransport sets the RoundTripper that actually sends the
// authenticated requests, allowing custom TLS settings, timeouts or proxies.
// Defaults to http.DefaultTransport, or an NTLM-compatible transport when
// WithNTLMFallback is set (one connection per host, HTTP/2 disabled).
func WithClientBaseTransport(rt http.RoundTripper) ClientTransportOption {
	return func(c *clientTransportConfig) {
		c.base = rt
	}
}

// WithNTLMFallback enables NTLM-within-SPNEGO as a fallback when the server
// returns a bare 401 to the initial Kerberos attempt. This mirrors how
// browsers handle the Negotiate scheme: Kerberos is tried first, and NTLM is
// used when Kerberos fails or the SPN is unknown to the KDC.
//
// When this option is set, the default base transport is replaced with one
// that pins connections and disables HTTP/2, since NTLM binds its handshake
// state to the underlying TCP connection. Requests are also serialised so that
// two NTLM handshakes cannot interleave on the same connection.
func WithNTLMFallback() ClientTransportOption {
	return func(c *clientTransportConfig) {
		c.ntlmFallback = true
	}
}

// ntlmCompatibleTransport returns a transport suitable for NTLM-within-SPNEGO:
// a single connection per host with HTTP/2 disabled. NTLM binds its
// half-finished handshake to the TCP connection the challenge arrived on, so
// both legs must travel the same one.
func ntlmCompatibleTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxConnsPerHost = 1
	t.MaxIdleConnsPerHost = 1
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	return t
}

// NewNegotiateTransport returns an http.RoundTripper that authenticates every
// outbound request to spn with Kerberos (SPNEGO), using the calling process's
// own Windows credentials — for a service, the identity of the account it runs
// under. No keytab or stored password is involved and no user is impersonated,
// so every request reaches the target as the service account itself.
//
// spn is the target's Service Principal Name, e.g. "HTTP/api.example.local".
//
// Pass WithNTLMFallback to also attempt NTLM-within-SPNEGO when the server
// rejects Kerberos with a bare 401. This matches browser behaviour and is
// useful when the SPN may not be registered or Kerberos is unavailable.
//
// The returned io.Closer releases the Windows SSPI credentials; call it on
// shutdown once the last request has completed. Credentials are acquired here
// rather than lazily so that a misconfigured service account surfaces at
// startup instead of on the first request.
//
// Use it as the Transport of an http.Client:
//
//	rt, closer, err := gwim.NewNegotiateTransport("HTTP/api.example.local")
//	if err != nil {
//		return err
//	}
//	defer closer.Close()
//	client := &http.Client{Transport: rt, Timeout: 15 * time.Second}
//
// Requests with a body should be built with http.NewRequest and a
// *bytes.Reader, *bytes.Buffer or *strings.Reader so that the body can be
// replayed if the server requires more than one negotiation leg.
func NewNegotiateTransport(spn string, opts ...ClientTransportOption) (http.RoundTripper, io.Closer, error) {
	cfg := applyClientTransportOptions(opts)

	if cfg.base == nil && cfg.ntlmFallback {
		cfg.base = ntlmCompatibleTransport()
	}

	transport, err := iauth.NewNegotiateTransport(spn, cfg.ntlmFallback, cfg.base)
	if err != nil {
		return nil, nil, err
	}
	return transport, transport, nil
}

func applyClientTransportOptions(opts []ClientTransportOption) *clientTransportConfig {
	cfg := &clientTransportConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return cfg
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
	existing := server.ConnContext
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if existing != nil {
			ctx = existing(ctx, c)
		}
		return context.WithValue(ctx, iauth.ContextKeyConnID, atomic.AddUint64(&connID, 1))
	}
}
