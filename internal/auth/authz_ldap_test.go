// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// mockLdapClient is a mock implementation of the ldapClient interface.
type mockLdapClient struct {
	SearchFunc             func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	CloseFunc              func() error
	TLSConnectionStateFunc func() (tls.ConnectionState, bool)
	GSSAPIBindFunc         func(client ldap.GSSAPIClient, target, password string) error
}

func (m *mockLdapClient) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.SearchFunc != nil {
		return m.SearchFunc(searchRequest)
	}
	return &ldap.SearchResult{}, nil
}

func (m *mockLdapClient) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func (m *mockLdapClient) TLSConnectionState() (tls.ConnectionState, bool) {
	if m.TLSConnectionStateFunc != nil {
		return m.TLSConnectionStateFunc()
	}
	return tls.ConnectionState{}, true
}

func (m *mockLdapClient) GSSAPIBind(client ldap.GSSAPIClient, target, password string) error {
	if m.GSSAPIBindFunc != nil {
		return m.GSSAPIBindFunc(client, target, password)
	}
	return nil
}

func TestCreateChannelBindings(t *testing.T) {
	certRaw := []byte("test certificate raw bytes")
	bindings, err := createChannelBindings(certRaw)
	if err != nil {
		t.Fatalf("createChannelBindings() unexpected error: %v", err)
	}

	if len(bindings) == 0 {
		t.Fatal("Expected non-empty channel bindings")
	}

	// Basic check for GSS channel bindings header
	if len(bindings) < 32 {
		t.Fatalf("Bindings too short: %d bytes", len(bindings))
	}
}

func TestGetUserGroups(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		searchSetup func(m *mockLdapClient)
		expected    []string
		wantErr     bool
	}{
		{
			name:     "Success",
			username: "testuser",
			searchSetup: func(m *mockLdapClient) {
				m.SearchFunc = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					if req.Scope == ldap.ScopeWholeSubtree && req.Filter == "(&(sAMAccountName=testuser)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{DN: "CN=testuser,OU=Users,DC=example,DC=com"},
							},
						}, nil
					}
					if req.BaseDN == "CN=testuser,OU=Users,DC=example,DC=com" && req.Scope == ldap.ScopeBaseObject {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{
									DN: "CN=testuser,OU=Users,DC=example,DC=com",
									Attributes: []*ldap.EntryAttribute{
										{Name: "tokenGroups", ByteValues: [][]byte{[]byte("g1"), []byte("g2")}},
									},
								},
							},
						}, nil
					}
					// \67\31 -> "g1", \67\32 -> "g2"
					if req.Filter == "(|(objectSid=\\67\\31)(objectSid=\\67\\32))" {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{DN: "CN=Group1,OU=Groups,DC=example,DC=com"},
								{DN: "CN=Group2,OU=Groups,DC=example,DC=com"},
							},
						}, nil
					}
					return &ldap.SearchResult{}, nil
				}
			},
			expected: []string{
				"CN=Group1,OU=Groups,DC=example,DC=com",
				"CN=Group2,OU=Groups,DC=example,DC=com",
			},
			wantErr: false,
		},
		{
			name:     "UserNotFound",
			username: "nonexistent",
			searchSetup: func(m *mockLdapClient) {
				m.SearchFunc = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
				}
			},
			expected: []string{},
			wantErr:  false,
		},
		{
			name:     "SearchError",
			username: "testuser",
			searchSetup: func(m *mockLdapClient) {
				m.SearchFunc = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					return nil, fmt.Errorf("LDAP error")
				}
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "BatchedSearch",
			username: "testuser",
			searchSetup: func(m *mockLdapClient) {
				// 101 SIDs forces two batches: [0..99] and [100].
				sids := make([][]byte, 101)
				for i := range sids {
					sids[i] = []byte{byte(i)}
				}
				batchCall := 0
				m.SearchFunc = func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					if req.BaseDN == "OU=Users,DC=example,DC=com" {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{DN: "CN=testuser,OU=Users,DC=example,DC=com"},
							},
						}, nil
					}
					if req.BaseDN == "CN=testuser,OU=Users,DC=example,DC=com" {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{
									DN: "CN=testuser,OU=Users,DC=example,DC=com",
									Attributes: []*ldap.EntryAttribute{
										{Name: "tokenGroups", ByteValues: sids},
									},
								},
							},
						}, nil
					}
					// Each group batch search returns one group entry.
					batchCall++
					return &ldap.SearchResult{
						Entries: []*ldap.Entry{
							{DN: fmt.Sprintf("CN=Group%d,OU=Groups,DC=example,DC=com", batchCall)},
						},
					}, nil
				}
			},
			expected: []string{
				"CN=Group1,OU=Groups,DC=example,DC=com",
				"CN=Group2,OU=Groups,DC=example,DC=com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockLdapClient{}
			tt.searchSetup(m)

			groups, err := getUserGroups(m, "OU=Users,DC=example,DC=com", tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("getUserGroups() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(groups, tt.expected) {
				t.Errorf("getUserGroups() = %v, want %v", groups, tt.expected)
			}
		})
	}
}

func TestLdapGroupProvider(t *testing.T) {
	const wantTimeout = 5 * time.Second

	serverInfo := LdapServerInfo{
		Address: "ldap.example.com:636",
		UsersDN: "OU=Users,DC=example,DC=com",
		Timeout: wantTimeout,
	}

	originalConnector := currentLdapConnector
	defer func() { currentLdapConnector = originalConnector }()

	t.Run("MiddlewareInjection", func(t *testing.T) {
		m := &mockLdapClient{
			SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				// Mock for the pool check search
				if req.BaseDN == "" {
					return &ldap.SearchResult{}, nil
				}
				// Mock for user search
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "CN=testuser,OU=Users,DC=example,DC=com"},
					},
				}, nil
			},
		}

		currentLdapConnector = func(l LdapServerInfo) (ldapClient, error) {
			if l.Timeout != wantTimeout {
				t.Errorf("connector received Timeout = %v, want %v", l.Timeout, wantTimeout)
			}
			return m, nil
		}

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			groups, ok := r.Context().Value(ContextKeyUserGroups).([]string)
			if !ok {
				t.Error("Groups not found in context")
			}
			if len(groups) != 0 {
				t.Errorf("Expected 0 groups, got %d", len(groups))
			}
		})

		mw, _ := LdapGroupProvider(serverInfo, DefaultAuthErrorHandlers())
		handler := mw(nextHandler)

		req := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), ContextKeyUsername, "testuser")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status OK, got %d", rr.Code)
		}
	})
}
