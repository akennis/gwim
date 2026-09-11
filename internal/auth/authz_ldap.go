// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alexbrainman/sspi/kerberos"
	"github.com/go-ldap/ldap/v3"
)

// Sentinel errors returned by the group-lookup path. Callers classify a failure
// with errors.Is instead of inspecting its message; the concrete error from the
// directory is wrapped alongside the sentinel and stays available.
var (
	// ErrLDAPConnection reports that the directory could not be reached or the
	// service-account bind failed. The user's group membership is unknown.
	ErrLDAPConnection = errors.New("ldap: connection failed")

	// ErrLDAPLookup reports that the directory was reachable but the search
	// itself failed. The user's group membership is unknown.
	ErrLDAPLookup = errors.New("ldap: lookup failed")

	// ErrUserNotFound reports that the directory answered and the account does
	// not exist, is disabled, or resolves ambiguously. Unlike the other two this
	// is a definitive answer rather than an outage, so callers should treat it as
	// a clean deny and not as a server error. It wraps ErrLDAPLookup, so code
	// that only separates connection failures from lookup failures still works.
	ErrUserNotFound = fmt.Errorf("%w: user not found", ErrLDAPLookup)
)

// ldapPoolSize is the number of idle LDAP connections kept per GroupLookup.
const ldapPoolSize = 10

type ldapPool chan pooledLdapClient

func (p ldapPool) Close() error {
	var errs []error
	for {
		select {
		case pc := <-p:
			if err := pc.client.Close(); err != nil {
				errs = append(errs, err)
			}
		default:
			return errors.Join(errs...)
		}
	}
}

type LdapServerInfo struct {
	Address           string
	UsersDN           string
	ServiceAccountSPN string
	// Timeout is the per-operation timeout applied to every LDAP call on the
	// connection (searches, health-check probes, etc.). Zero means no timeout.
	Timeout time.Duration
	// ConnectionTTL is the maximum lifetime of a pooled connection. Zero means no TTL.
	ConnectionTTL time.Duration
	// UserAttributes names additional Active Directory attributes to read for
	// the authenticated user - "mail" and "displayName", for example. They are
	// fetched by the same user-entry search that group resolution already
	// performs, so requesting them costs no extra round trip. The values are
	// surfaced on the request context under ContextKeyUserAttributes, keyed by
	// a lower-cased attribute name. distinguishedName is always read and need
	// not be listed here.
	UserAttributes []string
}

// userDirectory is the directory data resolved for one authenticated user: the
// group memberships as distinguished names, and the attributes requested via
// LdapServerInfo.UserAttributes keyed by a lower-cased name. An attribute the
// directory held no value for is simply absent from the map; the map itself is
// non-nil whenever the lookup reached the user entry.
type userDirectory struct {
	groups     []string
	attributes map[string][]string
}

// extraUserAttributes returns the caller-requested attribute names to add to
// the user-entry search, trimmed and de-duplicated and with distinguishedName
// (always requested) removed.
func extraUserAttributes(names []string) []string {
	seen := map[string]bool{"distinguishedname": true}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, name)
	}
	return out
}

// ldapClient defines the subset of ldap.Conn methods used by this package,
// allowing for easier mocking in tests.
type ldapClient interface {
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
	TLSConnectionState() (tls.ConnectionState, bool)
	GSSAPIBind(client ldap.GSSAPIClient, target, password string) error
}

// ldapWrapper wraps a *ldap.Conn to implement the LdapClient interface.
type ldapWrapper struct {
	*ldap.Conn
}

func connect(l LdapServerInfo) (ldapClient, error) {
	if len(l.Address) == 0 {
		return nil, fmt.Errorf("ldap address not specified")
	}

	host, _, err := net.SplitHostPort(l.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LDAP address: %w", err)
	}

	// The tls.Config is intentionally left with a nil RootCAs. As of Go 1.18,
	// Certificate.Verify uses platform APIs to verify certificates when the
	// Roots field is nil. On Windows, this prompts the crypto/x509 package
	// to load the trusted root certificates directly from the Windows system
	// certificate store. This ensures that the LDAP server's certificate is
	// validated against the CAs trusted by the host OS, which is the idiomatic
	// way to prevent Man-in-the-Middle (MITM) attacks on Windows.
	// For more details, see the crypto/x509 section of the Go 1.18 release notes:
	// https://go.dev/doc/go1.18#crypto/x509
	tlsConfig := &tls.Config{
		ServerName: host,
	}

	ldapURL := "ldaps://" + l.Address
	conn, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	if l.Timeout > 0 {
		conn.SetTimeout(l.Timeout)
	}

	cred, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to acquire current user credentials: %v", err)
	}
	defer cred.Release()

	var cbt []byte
	state, ok := conn.TLSConnectionState()
	if ok && len(state.PeerCertificates) > 0 {
		cbt, err = createChannelBindings(state.PeerCertificates[0].Raw)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to create channel bindings: %w", err)
		}
	}

	client := &sspiGssapiClient{cred: cred, channelBindings: cbt}
	err = conn.GSSAPIBind(client, l.ServiceAccountSPN, "")
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("LDAP GSSAPI Bind failed: %v", err)
	}
	return &ldapWrapper{conn}, nil
}

func createChannelBindings(certRaw []byte) ([]byte, error) {
	h := sha256.Sum256(certRaw)
	appData := append([]byte("tls-server-end-point:"), h[:]...)

	hdr := gssChannelBindings{
		ApplicationDataLen:    uint32(len(appData)),
		ApplicationDataOffset: uint32(binary.Size(gssChannelBindings{})),
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		return nil, fmt.Errorf("failed to write GSS channel bindings header: %w", err)
	}
	buf.Write(appData)
	return buf.Bytes(), nil
}

func getUserDirectory(ctx context.Context, ldapServiceConn ldapClient, info LdapServerInfo, username string) (userDirectory, error) {
	ldapUsersDN := info.UsersDN

	// First, get the user's distinguished name (DN), plus any additional
	// attributes the caller asked for - they ride along on this one search.
	extraAttrs := extraUserAttributes(info.UserAttributes)
	userSearchRequest := ldap.NewSearchRequest(
		ldapUsersDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		// Find the active user by their sAMAccountName.
		fmt.Sprintf("(&(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", ldap.EscapeFilter(username)),
		append([]string{"distinguishedName"}, extraAttrs...),
		nil,
	)
	userSearchResult, err := ldapServiceConn.Search(userSearchRequest)
	if err != nil {
		return userDirectory{}, fmt.Errorf("user search failed for %q: %w", username, err)
	}
	if len(userSearchResult.Entries) != 1 {
		// Zero entries means no such account, or one disabled by the
		// userAccountControl clause in the filter above. More than one means an
		// ambiguous sAMAccountName. Neither yields a group set worth trusting,
		// so both are a definitive deny rather than an empty membership.
		return userDirectory{}, fmt.Errorf("%w: %d entries matched %q", ErrUserNotFound, len(userSearchResult.Entries), username)
	}
	userEntry := userSearchResult.Entries[0]
	userDN := userEntry.DN
	if userDN == "" {
		return userDirectory{}, fmt.Errorf("%w: empty distinguishedName for %q", ErrUserNotFound, username)
	}

	// The user entry is in hand; pull the requested attributes off it now so
	// every return below carries them, group lookup outcome notwithstanding.
	// Match the directory's returned names case-insensitively - a caller may
	// ask for "Mail" and get back "mail".
	attributes := make(map[string][]string, len(extraAttrs))
	if len(extraAttrs) > 0 {
		wanted := make(map[string]bool, len(extraAttrs))
		for _, name := range extraAttrs {
			wanted[strings.ToLower(name)] = true
		}
		for _, attr := range userEntry.Attributes {
			key := strings.ToLower(attr.Name)
			if wanted[key] && len(attr.Values) > 0 {
				attributes[key] = attr.Values
			}
		}
	}

	// Now get the tokenGroups attribute for the user.
	tokenGroupsSearchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", // any object
		[]string{"tokenGroups"},
		nil,
	)
	tokenGroupsSearchResult, err := ldapServiceConn.Search(tokenGroupsSearchRequest)
	if err != nil {
		// This can fail if the constructed attribute is not available.
		// The error from AD is "00002120: SvcErr: DSID-03140594, problem 5012 (DIR_ERROR), data 0"
		return userDirectory{}, fmt.Errorf("user search for tokenGroups failed for user DN %q: %w", userDN, err)
	}
	if len(tokenGroupsSearchResult.Entries) != 1 {
		return userDirectory{groups: []string{}, attributes: attributes}, nil
	}

	groupSidsBytes := tokenGroupsSearchResult.Entries[0].GetRawAttributeValues("tokenGroups")
	if len(groupSidsBytes) == 0 {
		return userDirectory{groups: []string{}, attributes: attributes}, nil
	}

	// The UserDN might be scoped to an OU (e.g., OU=users,DC=example,DC=com).
	// To find all groups, we should search from the directory root (e.g., DC=example,DC=com).
	// We can derive this root by extracting the DC components from the provided UsersDN.
	var rootDN string
	parts := strings.Split(strings.ToLower(ldapUsersDN), ",")
	var dcParts []string
	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if strings.HasPrefix(trimmedPart, "dc=") {
			dcParts = append(dcParts, trimmedPart)
		}
	}
	if len(dcParts) > 0 {
		rootDN = strings.Join(dcParts, ",")
	} else {
		// As a fallback, use the original UsersDN if no DC components were found.
		rootDN = ldapUsersDN
	}

	// Search for groups in batches to avoid exceeding the LDAP server's
	// maximum filter size, which can be hit by users with many group memberships.
	const sidBatchSize = 100
	var groups []string
	for i := 0; i < len(groupSidsBytes); i += sidBatchSize {
		// A caller that has already given up is not worth another batch of
		// directory load; bail before issuing it rather than after.
		if err := ctx.Err(); err != nil {
			return userDirectory{}, err
		}
		end := i + sidBatchSize
		if end > len(groupSidsBytes) {
			end = len(groupSidsBytes)
		}

		var filterBuilder strings.Builder
		filterBuilder.WriteString("(|")
		for _, sidBytes := range groupSidsBytes[i:end] {
			// The SID needs to be escaped for the filter.
			filterBuilder.WriteString("(objectSid=")
			for _, b := range sidBytes {
				filterBuilder.WriteString(fmt.Sprintf("\\%02x", b))
			}
			filterBuilder.WriteString(")")
		}
		filterBuilder.WriteString(")")

		groupSearchRequest := ldap.NewSearchRequest(
			rootDN, // Search from the derived root DN to find all groups.
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filterBuilder.String(),
			// We want the distinguished names (DNs) of the groups.
			[]string{"dn"},
			nil,
		)
		groupSearchResult, err := ldapServiceConn.Search(groupSearchRequest)
		if err != nil {
			return userDirectory{}, fmt.Errorf("group search by SID failed for user %q: %w", username, err)
		}
		for _, entry := range groupSearchResult.Entries {
			groups = append(groups, entry.DN)
		}
	}

	if len(groups) == 0 {
		groups = []string{}
	}
	return userDirectory{groups: groups, attributes: attributes}, nil
}

// ldapConnector defines a function type for creating an LDAP connection.
type ldapConnector func(l LdapServerInfo) (ldapClient, error)

// currentLdapConnector is the function used to connect to LDAP, can be overridden for testing.
var currentLdapConnector ldapConnector = connect

type pooledLdapClient struct {
	client    ldapClient
	createdAt time.Time
}

// ValidateLDAP performs a lightweight connection and search against the LDAP
// server to verify that the configuration is valid and the server is reachable.
func ValidateLDAP(l LdapServerInfo) error {
	client, err := currentLdapConnector(l)
	if err != nil {
		return err
	}
	defer client.Close()

	// Perform a RootDSE search as a lightweight connectivity check.
	searchRequest := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"dn"}, nil,
	)
	sr, err := client.Search(searchRequest)
	if err != nil {
		return err
	}
	if len(sr.Entries) == 0 {
		return fmt.Errorf("LDAP validation failed: no entries returned for RootDSE search")
	}
	return nil
}

// GroupLookup owns a pool of LDAP connections and resolves a user's Active
// Directory group memberships two ways: as HTTP middleware that enriches an
// authenticated request's context, and as a synchronous Groups call for callers
// outside a request — a periodic re-check behind a cache, for instance.
type GroupLookup struct {
	info LdapServerInfo
	opts AuthErrorHandlers
	pool ldapPool

	// mu guards closed and serializes it against put, so a connection
	// returned by a lookup that is still in flight when Close runs can never
	// be pushed into the pool after Close has finished draining it — which
	// would otherwise leak that connection for good.
	mu     sync.Mutex
	closed bool
}

// NewGroupLookup returns a GroupLookup for the given directory. Connections are
// dialed lazily; nothing contacts the directory until the first lookup.
func NewGroupLookup(info LdapServerInfo, opts AuthErrorHandlers) *GroupLookup {
	opts.ApplyGeneralError()
	return &GroupLookup{info: info, opts: opts, pool: make(ldapPool, ldapPoolSize)}
}

// Close drains the connection pool, closing every idle connection, and marks
// the pool closed so any lookup still in flight closes its connection instead
// of returning it to the pool once it finishes.
func (g *GroupLookup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return g.pool.Close()
}

// put returns conn to the pool, closing it instead when the pool has already
// been closed or is already full.
func (g *GroupLookup) put(conn ldapClient, createdAt time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		conn.Close()
		return
	}
	select {
	case g.pool <- pooledLdapClient{client: conn, createdAt: createdAt}:
	default:
		conn.Close()
	}
}

// directory resolves username's group memberships and requested attributes on
// a connection taken from the pool, returning that connection to the pool when
// it is still usable.
//
// A lookup that fails on a pooled connection is assumed to have hit a stale
// one, so the connection is closed and the lookup retried exactly once on a
// freshly dialed connection. A connection that was freshly dialed to begin
// with (the pool was empty) is never stale, so its failures are not retried —
// retrying it would only double the latency and directory load for a
// legitimate failure. ErrUserNotFound is a definitive answer from a healthy
// connection either way and is returned without a retry.
//
// ctx is checked before dialing a new connection and before each batch of
// group lookups, so a caller that has already given up does not cause this
// background lookup to keep piling connections and searches onto the
// directory.
//
// Every error wraps ErrLDAPConnection or ErrLDAPLookup.
func (g *GroupLookup) directory(ctx context.Context, username string) (userDirectory, error) {
	var conn ldapClient
	var createdAt time.Time
	fromPool := false

	// Try to get a connection from the pool.
	select {
	case pooled := <-g.pool:
		conn = pooled.client
		createdAt = pooled.createdAt
		fromPool = true

		if g.info.ConnectionTTL > 0 && time.Since(createdAt) > g.info.ConnectionTTL {
			conn.Close()
			conn = nil
			fromPool = false
		}
	default:
		// Pool is empty.
	}

	if conn == nil {
		if err := ctx.Err(); err != nil {
			return userDirectory{}, err
		}
		var err error
		conn, err = currentLdapConnector(g.info)
		if err != nil {
			return userDirectory{}, fmt.Errorf("%w: %w", ErrLDAPConnection, err)
		}
		createdAt = time.Now()
	}

	dir, err := getUserDirectory(ctx, conn, g.info, username)
	if err != nil && fromPool && !errors.Is(err, ErrUserNotFound) {
		// The pooled connection may be stale — close it and retry once with a
		// freshly dialed connection.
		firstErr := err
		conn.Close()

		if ctxErr := ctx.Err(); ctxErr != nil {
			return userDirectory{}, ctxErr
		}
		conn, err = currentLdapConnector(g.info)
		if err != nil {
			// Preserve both the failure that prompted the retry and the
			// dial failure that followed it.
			return userDirectory{}, fmt.Errorf("%w: %w", ErrLDAPConnection, errors.Join(firstErr, err))
		}
		createdAt = time.Now()

		dir, err = getUserDirectory(ctx, conn, g.info, username)
	}

	switch {
	case err == nil:
		g.put(conn, createdAt)
		return dir, nil
	case errors.Is(err, ErrUserNotFound):
		// The directory answered, so the connection is still good.
		g.put(conn, createdAt)
		return userDirectory{}, err
	default:
		conn.Close()
		return userDirectory{}, fmt.Errorf("%w: %w", ErrLDAPLookup, err)
	}
}

// Groups returns username's Active Directory group memberships as distinguished
// names, using the same pooled connections and service-account bind as
// Middleware. username is normalized the same way the authentication
// middleware normalizes it (stripping a DOMAIN\ prefix or @REALM suffix and
// lowercasing), so a token-derived username works the same here as it does
// through Middleware. Errors wrap ErrLDAPConnection, ErrLDAPLookup, or
// ErrUserNotFound.
//
// ctx is honored as a deadline on the caller's wait, not as a cancellation of
// the search itself: the go-ldap client sets its timeout per connection, so an
// in-flight search cannot be interrupted. When ctx is done first, Groups returns
// ctx.Err() promptly and the search continues in the background, bounded by the
// per-operation LdapServerInfo.Timeout, after which its connection returns to
// the pool. The effective wait is therefore min(ctx deadline, Timeout). The
// background lookup does check ctx before starting any new expensive work of
// its own — dialing a replacement connection, or issuing another batch of
// group searches — so a burst of abandoned calls does not pile unbounded
// connections onto the directory.
func (g *GroupLookup) Groups(ctx context.Context, username string) ([]string, error) {
	username = NormalizeUsername(username)
	if username == "" {
		return nil, fmt.Errorf("%w: empty username", ErrUserNotFound)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	type lookup struct {
		dir userDirectory
		err error
	}
	// Buffered so an abandoned lookup never blocks its goroutine forever.
	done := make(chan lookup, 1)
	go func() {
		dir, err := g.directory(ctx, username)
		done <- lookup{dir, err}
	}()

	select {
	case r := <-done:
		return r.dir.groups, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Middleware satisfies func(http.Handler) http.Handler. It injects the
// authenticated caller's group memberships into the request context under
// ContextKeyUserGroups - and, when LdapServerInfo.UserAttributes is set, their
// requested directory attributes under ContextKeyUserAttributes. It must run
// after authentication has placed the username under ContextKeyUsername.
func (g *GroupLookup) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the enriched values are already in the context, do nothing. When
		// attributes are configured, both must be present to skip: a resumed
		// session that restored only groups still needs the attribute lookup.
		_, haveGroups := r.Context().Value(ContextKeyUserGroups).([]string)
		_, haveAttrs := r.Context().Value(ContextKeyUserAttributes).(map[string][]string)
		if haveGroups && (haveAttrs || len(g.info.UserAttributes) == 0) {
			next.ServeHTTP(w, r)
			return
		}

		username, ok := r.Context().Value(ContextKeyUsername).(string)
		if !ok || username == "" {
			// This should not happen if SPNEGOMiddleware is working, but we check for safety.
			g.opts.GetOnUnauthorized()(w, r, fmt.Errorf("user not found in context"))
			return
		}

		dir, err := g.directory(r.Context(), username)
		switch {
		case err == nil:
		case errors.Is(err, ErrUserNotFound):
			// An account the directory does not know has no memberships. Let it
			// through with an empty set so authorization downstream denies it;
			// a deleted or disabled account is not a server error.
			dir = userDirectory{groups: []string{}, attributes: map[string][]string{}}
		case errors.Is(err, ErrLDAPConnection):
			g.opts.GetOnLdapConnectionError()(w, r, err)
			return
		default:
			g.opts.GetOnLdapLookupError()(w, r, err)
			return
		}

		ctx := context.WithValue(r.Context(), ContextKeyUserGroups, dir.groups)
		if len(g.info.UserAttributes) > 0 {
			attrs := dir.attributes
			if attrs == nil {
				attrs = map[string][]string{}
			}
			ctx = context.WithValue(ctx, ContextKeyUserAttributes, attrs)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LdapGroupProvider returns the group-injecting middleware described on
// GroupLookup.Middleware, plus a Closer that drains its connection pool.
// NewGroupLookup offers the same middleware alongside the synchronous Groups
// lookup; this remains the convenient form when only the middleware is wanted.
func LdapGroupProvider(ldapServerInfo LdapServerInfo, opts AuthErrorHandlers) (func(http.Handler) http.Handler, io.Closer) {
	g := NewGroupLookup(ldapServerInfo, opts)
	return g.Middleware, g
}
