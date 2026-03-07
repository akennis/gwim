package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/alexbrainman/sspi/kerberos"
	"github.com/go-ldap/ldap/v3"
)

type LdapServerInfo struct {
	Address           string
	UsersDN           string
	ServiceAccountSPN string
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

	cred, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to acquire current user credentials: %v", err)
	}
	defer cred.Release()

	var cbt []byte
	state, ok := conn.TLSConnectionState()
	if ok && len(state.PeerCertificates) > 0 {
		cbt = createChannelBindings(state.PeerCertificates[0].Raw)
	}

	client := &sspiGssapiClient{cred: cred, channelBindings: cbt}
	err = conn.GSSAPIBind(client, l.ServiceAccountSPN, "")
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("LDAP GSSAPI Bind failed: %v", err)
	}
	return &ldapWrapper{conn}, nil
}

func createChannelBindings(certRaw []byte) []byte {
	h := sha256.Sum256(certRaw)
	appData := append([]byte("tls-server-end-point:"), h[:]...)

	hdr := gssChannelBindings{
		ApplicationDataLen:    uint32(len(appData)),
		ApplicationDataOffset: uint32(binary.Size(gssChannelBindings{})),
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, hdr)
	buf.Write(appData)
	return buf.Bytes()
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

	// Now we have the SIDs, we build a filter to find all matching groups.
	var filterBuilder strings.Builder
	filterBuilder.WriteString("(|")
	for _, sidBytes := range groupSidsBytes {
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

	if len(groupSearchResult.Entries) == 0 {
		return []string{}, nil
	}

	groups := make([]string, len(groupSearchResult.Entries))
	for i, entry := range groupSearchResult.Entries {
		groups[i] = entry.DN
	}

	return groups, nil
}

// ldapConnector defines a function type for creating an LDAP connection.
type ldapConnector func(l LdapServerInfo) (ldapClient, error)

// currentLdapConnector is the function used to connect to LDAP, can be overridden for testing.
var currentLdapConnector ldapConnector = connect

func LdapGroupProvider(ldapServerInfo LdapServerInfo, options ...AuthOptions) func(http.Handler) http.Handler {
	ldapPool := make(chan ldapClient, 10)
	var opts AuthOptions
	if len(options) > 0 {
		opts = options[0]
	}
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
			var err error

			// Try to get a connection from the pool
			select {
			case ldapServiceConn = <-ldapPool:
				// We got a connection from the pool. Let's check if it's still alive.
				// A simple search is a good way to do this.
				searchRequest := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil)
				if _, err := ldapServiceConn.Search(searchRequest); err != nil {
					// Connection is likely stale. Close it and prepare to create a new one.
					ldapServiceConn.Close()
					ldapServiceConn = nil
				}
			default:
				// Pool is empty, will create a new connection below.
			}

			if ldapServiceConn == nil {
				// Create a new connection if the pool was empty or the connection from the pool was stale.
				ldapServiceConn, err = currentLdapConnector(ldapServerInfo)
				if err != nil {
					opts.GetOnLdapConnectionError()(w, r, err)
					return
				}
			}

			userGroups, err := getUserGroups(ldapServiceConn, ldapServerInfo.UsersDN, username)
			if err != nil {
				// On error, close the connection and don't return it to the pool
				ldapServiceConn.Close()
				opts.GetOnLdapLookupError()(w, r, err)
				return
			}

			// If successful, try to return the connection to the pool
			select {
			case ldapPool <- ldapServiceConn:
			default:
				// Pool is full, close the connection
				ldapServiceConn.Close()
			}

			ctx := context.WithValue(r.Context(), ContextKeyUserGroups, userGroups)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
