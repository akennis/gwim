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
	"time"

	"github.com/alexbrainman/sspi/kerberos"
	"github.com/go-ldap/ldap/v3"
)

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

func getUserGroups(ldapServiceConn ldapClient, ldapUsersDN string, username string) ([]string, error) {
	// First, get the user's distinguished name (DN).
	userSearchRequest := ldap.NewSearchRequest(
		ldapUsersDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		// Find the active user by their sAMAccountName.
		fmt.Sprintf("(&(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", ldap.EscapeFilter(username)),
		// We only need the distinguishedName.
		[]string{"distinguishedName"},
		nil,
	)
	userSearchResult, err := ldapServiceConn.Search(userSearchRequest)
	if err != nil {
		return nil, fmt.Errorf("user search failed for %q: %w", username, err)
	}
	if len(userSearchResult.Entries) != 1 {
		// User not found or multiple entries found.
		return []string{}, nil
	}
	userDN := userSearchResult.Entries[0].DN
	if userDN == "" {
		return []string{}, nil
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
		return nil, fmt.Errorf("user search for tokenGroups failed for user DN %q: %w", userDN, err)
	}
	if len(tokenGroupsSearchResult.Entries) != 1 {
		return []string{}, nil
	}

	groupSidsBytes := tokenGroupsSearchResult.Entries[0].GetRawAttributeValues("tokenGroups")
	if len(groupSidsBytes) == 0 {
		return []string{}, nil
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
			return nil, fmt.Errorf("group search by SID failed for user %q: %w", username, err)
		}
		for _, entry := range groupSearchResult.Entries {
			groups = append(groups, entry.DN)
		}
	}

	if len(groups) == 0 {
		return []string{}, nil
	}
	return groups, nil
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

func LdapGroupProvider(ldapServerInfo LdapServerInfo, opts AuthErrorHandlers) (func(http.Handler) http.Handler, io.Closer) {
	pool := make(ldapPool, 10)
	opts.ApplyGeneralError()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If groups are already in the context, do nothing.
			if _, ok := r.Context().Value(ContextKeyUserGroups).([]string); ok {
				next.ServeHTTP(w, r)
				return
			}

			username, ok := r.Context().Value(ContextKeyUsername).(string)
			if !ok || username == "" {
				// This should not happen if SPNEGOMiddleware is working, but we check for safety.
				opts.GetOnUnauthorized()(w, r, fmt.Errorf("user not found in context"))
				return
			}

			var ldapServiceConn ldapClient
			var connCreatedAt time.Time
			var err error

			// Try to get a connection from the pool
			select {
			case pooledConn := <-pool:
				ldapServiceConn = pooledConn.client
				connCreatedAt = pooledConn.createdAt

				if ldapServerInfo.ConnectionTTL > 0 && time.Since(connCreatedAt) > ldapServerInfo.ConnectionTTL {
					ldapServiceConn.Close()
					ldapServiceConn = nil
				}
			default:
				// Pool is empty
			}

			if ldapServiceConn == nil {
				ldapServiceConn, err = currentLdapConnector(ldapServerInfo)
				if err != nil {
					opts.GetOnLdapConnectionError()(w, r, err)
					return
				}
				connCreatedAt = time.Now()
			}

			userGroups, err := getUserGroups(ldapServiceConn, ldapServerInfo.UsersDN, username)
			if err != nil {
				// Pooled connection may be stale — close it and retry once with a fresh connection.
				ldapServiceConn.Close()
				ldapServiceConn, err = currentLdapConnector(ldapServerInfo)
				if err != nil {
					opts.GetOnLdapConnectionError()(w, r, err)
					return
				}
				connCreatedAt = time.Now()

				userGroups, err = getUserGroups(ldapServiceConn, ldapServerInfo.UsersDN, username)
				if err != nil {
					ldapServiceConn.Close()
					opts.GetOnLdapLookupError()(w, r, err)
					return
				}
			}

			// Return connection to pool
			select {
			case pool <- pooledLdapClient{client: ldapServiceConn, createdAt: connCreatedAt}:
			default:
				ldapServiceConn.Close()
			}

			ctx := context.WithValue(r.Context(), ContextKeyUserGroups, userGroups)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, pool
}
