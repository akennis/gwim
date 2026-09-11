// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// foundUserSearch answers the user-DN search with a single entry and every
// later search with nothing, so getUserGroups reaches its "user exists, no
// memberships" result without needing tokenGroups fixtures.
func foundUserSearch(groups ...string) func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	return func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.Scope {
		case ldap.ScopeWholeSubtree:
			if req.BaseDN == "OU=Users,DC=example,DC=com" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					{DN: "CN=testuser,OU=Users,DC=example,DC=com"},
				}}, nil
			}
			// Group search by SID.
			entries := make([]*ldap.Entry, 0, len(groups))
			for _, g := range groups {
				entries = append(entries, &ldap.Entry{DN: g})
			}
			return &ldap.SearchResult{Entries: entries}, nil
		default:
			// tokenGroups on the user's own DN.
			sids := make([][]byte, len(groups))
			for i := range sids {
				sids[i] = []byte{byte(i + 1)}
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{{
				DN:         "CN=testuser,OU=Users,DC=example,DC=com",
				Attributes: []*ldap.EntryAttribute{{Name: "tokenGroups", ByteValues: sids}},
			}}}, nil
		}
	}
}

func testServerInfo() LdapServerInfo {
	return LdapServerInfo{
		Address: "ldap.example.com:636",
		UsersDN: "OU=Users,DC=example,DC=com",
		Timeout: 5 * time.Second,
	}
}

// withConnector installs a connector for the duration of the test.
func withConnector(t *testing.T, c ldapConnector) {
	t.Helper()
	original := currentLdapConnector
	currentLdapConnector = c
	t.Cleanup(func() { currentLdapConnector = original })
}

func TestGroupLookupGroups(t *testing.T) {
	t.Run("FoundUserReturnsGroups", func(t *testing.T) {
		want := []string{
			"CN=Group1,OU=Groups,DC=example,DC=com",
			"CN=Group2,OU=Groups,DC=example,DC=com",
		}
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			return &mockLdapClient{SearchFunc: foundUserSearch(want...)}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		got, err := g.Groups(context.Background(), "testuser")
		if err != nil {
			t.Fatalf("Groups() unexpected error: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("Groups() = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Groups()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("NormalizesUsernameBeforeLookup", func(t *testing.T) {
		var gotFilter string
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			return &mockLdapClient{SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.Scope == ldap.ScopeWholeSubtree && req.BaseDN == "OU=Users,DC=example,DC=com" {
					gotFilter = req.Filter
				}
				return foundUserSearch()(req)
			}}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		// A token-derived username carries the same NetBIOS prefix and casing
		// the authentication middleware would otherwise have normalized away.
		if _, err := g.Groups(context.Background(), `EXAMPLE\TestUser`); err != nil {
			t.Fatalf("Groups() unexpected error: %v", err)
		}
		want := "(&(sAMAccountName=testuser)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		if gotFilter != want {
			t.Errorf("search filter = %q, want %q (username was not normalized)", gotFilter, want)
		}
	})

	t.Run("MissingUserReturnsErrUserNotFound", func(t *testing.T) {
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			return &mockLdapClient{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			}}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		_, err := g.Groups(context.Background(), "nonexistent")
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("Groups() error = %v, want ErrUserNotFound", err)
		}
		// A missing user is a lookup answer, not a connection failure.
		if !errors.Is(err, ErrLDAPLookup) {
			t.Errorf("ErrUserNotFound should wrap ErrLDAPLookup, got %v", err)
		}
		if errors.Is(err, ErrLDAPConnection) {
			t.Errorf("Groups() error = %v, should not be an ErrLDAPConnection", err)
		}
	})

	t.Run("EmptyUsernameReturnsErrUserNotFound", func(t *testing.T) {
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			t.Error("connector called for an empty username")
			return nil, fmt.Errorf("should not dial")
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		if _, err := g.Groups(context.Background(), ""); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("Groups() error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("ConnectFailureReturnsErrLDAPConnection", func(t *testing.T) {
		dialErr := errors.New("dial tcp: connection refused")
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			return nil, dialErr
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		_, err := g.Groups(context.Background(), "testuser")
		if !errors.Is(err, ErrLDAPConnection) {
			t.Fatalf("Groups() error = %v, want ErrLDAPConnection", err)
		}
		if errors.Is(err, ErrLDAPLookup) {
			t.Errorf("Groups() error = %v, should not also be an ErrLDAPLookup", err)
		}
		// The concrete cause stays reachable.
		if !errors.Is(err, dialErr) {
			t.Errorf("Groups() error = %v, want it to wrap %v", err, dialErr)
		}
	})

	t.Run("SearchFailureReturnsErrLDAPLookup", func(t *testing.T) {
		searchErr := errors.New("LDAP result code 80")
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			return &mockLdapClient{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, searchErr
			}}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		_, err := g.Groups(context.Background(), "testuser")
		if !errors.Is(err, ErrLDAPLookup) {
			t.Fatalf("Groups() error = %v, want ErrLDAPLookup", err)
		}
		if errors.Is(err, ErrLDAPConnection) {
			t.Errorf("Groups() error = %v, should not also be an ErrLDAPConnection", err)
		}
		if !errors.Is(err, searchErr) {
			t.Errorf("Groups() error = %v, want it to wrap %v", err, searchErr)
		}
	})

	t.Run("StaleConnectionRetriesExactlyOnce", func(t *testing.T) {
		var dials atomic.Int32
		staleClosed := make(chan struct{}, 1)

		// The connection that will be primed into the pool and later go stale.
		pooled := &mockLdapClient{
			SearchFunc: foundUserSearch("CN=Group1,OU=Groups,DC=example,DC=com"),
			CloseFunc: func() error {
				select {
				case staleClosed <- struct{}{}:
				default:
				}
				return nil
			},
		}
		fresh := &mockLdapClient{SearchFunc: foundUserSearch("CN=Group1,OU=Groups,DC=example,DC=com")}

		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			if dials.Add(1) == 1 {
				return pooled, nil
			}
			return fresh, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		// Prime the pool with a healthy, pooled connection.
		if _, err := g.Groups(context.Background(), "testuser"); err != nil {
			t.Fatalf("priming Groups() call unexpected error: %v", err)
		}
		if n := dials.Load(); n != 1 {
			t.Fatalf("priming dialled %d times, want 1", n)
		}

		// The pooled connection has now gone stale.
		pooled.SearchFunc = func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("connection reset")
		}

		got, err := g.Groups(context.Background(), "testuser")
		if err != nil {
			t.Fatalf("Groups() unexpected error after retry: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("Groups() = %v, want one group", got)
		}
		if n := dials.Load(); n != 2 {
			t.Errorf("dialled %d times, want exactly 2 (priming + one retry)", n)
		}
		select {
		case <-staleClosed:
		default:
			t.Error("stale connection was not closed before the retry")
		}
	})

	t.Run("RetryFailureDoesNotRetryAgain", func(t *testing.T) {
		var dials atomic.Int32
		pooled := &mockLdapClient{SearchFunc: foundUserSearch("CN=Group1,OU=Groups,DC=example,DC=com")}

		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			if dials.Add(1) == 1 {
				return pooled, nil
			}
			// The retry dial also produces a connection whose search fails.
			return &mockLdapClient{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, errors.New("connection reset")
			}}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		// Prime the pool with a healthy, pooled connection.
		if _, err := g.Groups(context.Background(), "testuser"); err != nil {
			t.Fatalf("priming Groups() call unexpected error: %v", err)
		}
		if n := dials.Load(); n != 1 {
			t.Fatalf("priming dialled %d times, want 1", n)
		}

		// The pooled connection has now gone stale.
		pooled.SearchFunc = func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("connection reset")
		}

		if _, err := g.Groups(context.Background(), "testuser"); !errors.Is(err, ErrLDAPLookup) {
			t.Fatalf("Groups() error = %v, want ErrLDAPLookup", err)
		}
		if n := dials.Load(); n != 2 {
			t.Errorf("dialled %d times, want exactly 2 — the retry must not loop", n)
		}
	})

	t.Run("FreshConnectionFailureIsNotRetried", func(t *testing.T) {
		var dials atomic.Int32
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			dials.Add(1)
			return &mockLdapClient{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, errors.New("connection reset")
			}}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		// The pool starts empty, so this connection is freshly dialed rather
		// than pooled — it was never stale, so a search failure on it must
		// not trigger a retry dial.
		if _, err := g.Groups(context.Background(), "testuser"); !errors.Is(err, ErrLDAPLookup) {
			t.Fatalf("Groups() error = %v, want ErrLDAPLookup", err)
		}
		if n := dials.Load(); n != 1 {
			t.Errorf("dialled %d times, want exactly 1 — a fresh connection's failure must not be retried", n)
		}
	})

	t.Run("MissingUserIsNotRetried", func(t *testing.T) {
		var dials atomic.Int32
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			dials.Add(1)
			return &mockLdapClient{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			}}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		if _, err := g.Groups(context.Background(), "nonexistent"); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("Groups() error = %v, want ErrUserNotFound", err)
		}
		if n := dials.Load(); n != 1 {
			t.Errorf("dialled %d times, want 1 — a definitive answer must not trigger a retry", n)
		}
	})

	t.Run("RetryDialFailurePreservesOriginalSearchError", func(t *testing.T) {
		var dials atomic.Int32
		pooled := &mockLdapClient{SearchFunc: foundUserSearch("CN=Group1,OU=Groups,DC=example,DC=com")}
		searchErr := errors.New("connection reset by peer")
		dialErr := errors.New("dial tcp: connection refused")

		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			if dials.Add(1) == 1 {
				return pooled, nil
			}
			return nil, dialErr
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		// Prime the pool with a healthy, pooled connection.
		if _, err := g.Groups(context.Background(), "testuser"); err != nil {
			t.Fatalf("priming Groups() call unexpected error: %v", err)
		}

		// The pooled connection has now gone stale, and the dial for the
		// retry that follows fails too.
		pooled.SearchFunc = func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, searchErr
		}

		_, err := g.Groups(context.Background(), "testuser")
		if !errors.Is(err, ErrLDAPConnection) {
			t.Fatalf("Groups() error = %v, want ErrLDAPConnection", err)
		}
		if !errors.Is(err, dialErr) {
			t.Errorf("Groups() error = %v, want it to wrap the retry dial failure %v", err, dialErr)
		}
		if !errors.Is(err, searchErr) {
			t.Errorf("Groups() error = %v, want it to also wrap %v, the original search failure that prompted the retry", err, searchErr)
		}
	})

	t.Run("AbortsBeforeDialingWhenContextAlreadyDone", func(t *testing.T) {
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			t.Error("connector called for an already-cancelled context")
			return nil, fmt.Errorf("should not dial")
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Calls the pool logic directly: Groups' own pre-flight ctx.Err()
		// check would otherwise short-circuit before this path is reached.
		if _, err := g.groups(ctx, "testuser"); !errors.Is(err, context.Canceled) {
			t.Fatalf("groups() error = %v, want context.Canceled", err)
		}
	})

	t.Run("AbortsBeforeRetryDialWhenContextAlreadyDone", func(t *testing.T) {
		var dials atomic.Int32
		pooled := &mockLdapClient{SearchFunc: foundUserSearch("CN=Group1,OU=Groups,DC=example,DC=com")}

		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			if dials.Add(1) == 1 {
				return pooled, nil
			}
			t.Error("connector called for a retry dial after the context was already done")
			return nil, fmt.Errorf("should not dial")
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		if _, err := g.Groups(context.Background(), "testuser"); err != nil {
			t.Fatalf("priming Groups() call unexpected error: %v", err)
		}

		pooled.SearchFunc = func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("connection reset")
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := g.groups(ctx, "testuser"); !errors.Is(err, context.Canceled) {
			t.Fatalf("groups() error = %v, want context.Canceled", err)
		}
		if n := dials.Load(); n != 1 {
			t.Errorf("dialled %d times, want 1 — the retry dial must not run once the context is already done", n)
		}
	})

	t.Run("HealthyConnectionIsPooled", func(t *testing.T) {
		var dials atomic.Int32
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			dials.Add(1)
			return &mockLdapClient{SearchFunc: foundUserSearch("CN=Group1,OU=Groups,DC=example,DC=com")}, nil
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		for i := 0; i < 3; i++ {
			if _, err := g.Groups(context.Background(), "testuser"); err != nil {
				t.Fatalf("Groups() call %d unexpected error: %v", i, err)
			}
		}
		if n := dials.Load(); n != 1 {
			t.Errorf("dialled %d times across 3 sequential lookups, want 1", n)
		}
	})

	t.Run("CancelledContextReturnsPromptly", func(t *testing.T) {
		release := make(chan struct{})
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			return &mockLdapClient{SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				<-release // Stand in for a directory that has stopped answering.
				return foundUserSearch()(req)
			}}, nil
		})
		defer close(release)

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})

		ctx, cancel := context.WithCancel(context.Background())
		returned := make(chan error, 1)
		go func() {
			_, err := g.Groups(ctx, "testuser")
			returned <- err
		}()

		cancel()
		select {
		case err := <-returned:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Groups() error = %v, want context.Canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Groups() did not return promptly after its context was cancelled")
		}
	})

	t.Run("AlreadyDoneContextSkipsTheLookup", func(t *testing.T) {
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			t.Error("connector called for an already-cancelled context")
			return nil, fmt.Errorf("should not dial")
		})

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
		defer g.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := g.Groups(ctx, "testuser"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Groups() error = %v, want context.Canceled", err)
		}
	})

	t.Run("ExpiredDeadlineReturnsDeadlineExceeded", func(t *testing.T) {
		release := make(chan struct{})
		withConnector(t, func(LdapServerInfo) (ldapClient, error) {
			return &mockLdapClient{SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				<-release
				return foundUserSearch()(req)
			}}, nil
		})
		defer close(release)

		g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := g.Groups(ctx, "testuser")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Groups() error = %v, want context.DeadlineExceeded", err)
		}
		// The wait must be bounded by the context, not by LdapServerInfo.Timeout.
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("Groups() took %v, want it bounded by the 50ms context deadline", elapsed)
		}
	})
}

// TestGroupLookupCloseDuringInFlightLookupClosesConnection guards against a
// leak where a lookup abandoned by its caller finishes after Close has
// already drained the pool: without tracking closed state, put would push
// that connection into a pool nothing will ever drain again.
func TestGroupLookupCloseDuringInFlightLookupClosesConnection(t *testing.T) {
	release := make(chan struct{})
	dialed := make(chan struct{})
	closedConn := make(chan struct{}, 1)

	withConnector(t, func(LdapServerInfo) (ldapClient, error) {
		close(dialed)
		return &mockLdapClient{
			SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				<-release // stand in for a search still in flight.
				return foundUserSearch()(req)
			},
			CloseFunc: func() error {
				select {
				case closedConn <- struct{}{}:
				default:
				}
				return nil
			},
		}, nil
	})

	g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})

	backgroundDone := make(chan struct{})
	go func() {
		g.groups(context.Background(), "testuser")
		close(backgroundDone)
	}()
	<-dialed // the lookup has dialed and is now blocked inside Search.

	// Close the pool while the lookup above is still in flight — this is the
	// window in which an unguarded put would leak the connection.
	if err := g.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	close(release)
	<-backgroundDone

	select {
	case <-closedConn:
	case <-time.After(time.Second):
		t.Error("connection returned by a lookup still in flight when Close ran was not closed — leaked")
	}
	select {
	case <-g.pool:
		t.Error("connection was pushed into the pool after Close had already drained it")
	default:
	}
}

// TestGroupLookupConcurrentGroups exercises the pool under concurrency; the
// race detector is what makes it worth running.
func TestGroupLookupConcurrentGroups(t *testing.T) {
	withConnector(t, func(LdapServerInfo) (ldapClient, error) {
		return &mockLdapClient{SearchFunc: foundUserSearch("CN=Group1,OU=Groups,DC=example,DC=com")}, nil
	})

	g := NewGroupLookup(testServerInfo(), AuthErrorHandlers{})
	defer g.Close()

	const workers = 32
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			_, err := g.Groups(context.Background(), "testuser")
			errs <- err
		}()
	}
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Groups() error: %v", err)
		}
	}
}
