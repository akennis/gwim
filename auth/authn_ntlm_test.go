// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexbrainman/sspi"
	"github.com/patrickmn/go-cache"
)

// mockNtlmServerContext implements ntlmServerContext
type mockNtlmServerContext struct {
	username      string
	updateErrs    []error
	updateIndex   int
	releaseCalled bool
}

func (m *mockNtlmServerContext) Update(outDesc, inDesc *sspi.SecBufferDesc) error {
	if outDesc != nil && outDesc.Buffers != nil {
		outDesc.Buffers.BufferSize = 0
	}
	if m.updateIndex >= len(m.updateErrs) {
		return fmt.Errorf("too many Update calls")
	}
	err := m.updateErrs[m.updateIndex]
	m.updateIndex++
	return err
}

func (m *mockNtlmServerContext) Release() error {
	m.releaseCalled = true
	return nil
}

func (m *mockNtlmServerContext) GetUsername() (string, error) {
	if m.username == "" {
		return "", fmt.Errorf("no username")
	}
	return m.username, nil
}

// mockNtlmProvider implements ntlmProvider
type mockNtlmProvider struct {
	contexts []*mockNtlmServerContext
	index    int
}

func (m *mockNtlmProvider) NewServerContext(creds *sspi.Credentials) ntlmServerContext {
	if m.index >= len(m.contexts) {
		return nil
	}
	ctx := m.contexts[m.index]
	m.index++
	return ctx
}

func TestNtlmAuthn(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func(r *http.Request) *http.Request
		authHeader     string
		mockProvider   *mockNtlmProvider
		expectedStatus int
		expectedUser   string
		expectWWWAuth  bool
		connID         uint64
	}{
		{
			name:       "Success_OneStep",
			authHeader: "NTLM " + base64.StdEncoding.EncodeToString([]byte("token")),
			mockProvider: &mockNtlmProvider{
				contexts: []*mockNtlmServerContext{
					{username: "DOMAIN\\testuser", updateErrs: []error{sspi.SEC_E_OK}},
				},
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "testuser",
			connID:         123,
		},
		{
			name:       "Success_TwoStep",
			authHeader: "NTLM " + base64.StdEncoding.EncodeToString([]byte("token")),
			mockProvider: &mockNtlmProvider{
				contexts: []*mockNtlmServerContext{
					{
						username:   "testuser@DOMAIN",
						updateErrs: []error{sspi.SEC_I_CONTINUE_NEEDED, sspi.SEC_E_OK},
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "testuser",
			connID:         456,
		},
		{
			name: "SkipIfAlreadyAuthenticated",
			setupContext: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), ContextKeyUsername, "existinguser")
				return r.WithContext(ctx)
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "existinguser",
		},
		{
			name:           "MissingAuthHeader",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectWWWAuth:  true,
		},
		{
			name:           "InvalidBase64Token",
			authHeader:     "NTLM invalid-base64-!!!",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:       "AuthenticationError",
			authHeader: "NTLM " + base64.StdEncoding.EncodeToString([]byte("token")),
			mockProvider: &mockNtlmProvider{
				contexts: []*mockNtlmServerContext{
					{updateErrs: []error{fmt.Errorf("sspi error")}},
				},
			},
			expectedStatus: http.StatusUnauthorized,
			connID:         789,
		},
		{
			name:       "MissingConnID",
			authHeader: "NTLM " + base64.StdEncoding.EncodeToString([]byte("token")),
			mockProvider: &mockNtlmProvider{
				contexts: []*mockNtlmServerContext{
					{updateErrs: []error{sspi.SEC_I_CONTINUE_NEEDED}},
				},
			},
			expectedStatus: http.StatusUnauthorized,
			connID:         0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCache := cache.New(1*time.Minute, 2*time.Minute)
			handler := ntlmAuthn(nil, tt.mockProvider, authCache, DefaultAuthOptions())
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				username, _ := r.Context().Value(ContextKeyUsername).(string)
				if username != tt.expectedUser {
					t.Errorf("Expected username %q, got %q", tt.expectedUser, username)
				}
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "http://example.com/foo", nil)
			if tt.setupContext != nil {
				req = tt.setupContext(req)
			}
			if tt.connID != 0 {
				ctx := context.WithValue(req.Context(), ContextKeyConnID, tt.connID)
				req = req.WithContext(ctx)
			}
			if tt.authHeader != "" {
				req.Header.Set(AUTHORIZATION, tt.authHeader)
			}

			rr := httptest.NewRecorder()

			if tt.name == "Success_TwoStep" {
				// Step 1
				handler(nextHandler).ServeHTTP(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("Step 1: expected 401, got %d", rr.Code)
				}

				// Step 2
				rr = httptest.NewRecorder()
				req.Header.Set(AUTHORIZATION, "NTLM "+base64.StdEncoding.EncodeToString([]byte("token2")))
				handler(nextHandler).ServeHTTP(rr, req)
			} else {
				handler(nextHandler).ServeHTTP(rr, req)
			}

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectWWWAuth {
				if rr.Header().Get(WWW_AUTH) != NTLM {
					t.Errorf("Expected %s header %q, got %q", WWW_AUTH, NTLM, rr.Header().Get(WWW_AUTH))
				}
			}
		})
	}
}

func TestNtlmAuthn_CustomHandlers(t *testing.T) {
	opts := AuthOptions{
		OnGeneralError: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusTeapot)
		},
	}
	opts.ApplyGeneralError()

	t.Run("OnGeneralError_Catchall", func(t *testing.T) {
		authCache := cache.New(1*time.Minute, 2*time.Minute)
		handler := ntlmAuthn(nil, nil, authCache, opts)
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		rr := httptest.NewRecorder()

		handler(nil).ServeHTTP(rr, req)

		if rr.Code != http.StatusTeapot {
			t.Errorf("Expected status %d, got %d", http.StatusTeapot, rr.Code)
		}
	})
}

func TestNtlmAuthn_CacheEviction(t *testing.T) {
	mockCtx := &mockNtlmServerContext{}
	authCache := cache.New(1*time.Millisecond, 1*time.Millisecond)

	// Setup eviction callback
	np := &mockNtlmProvider{contexts: []*mockNtlmServerContext{mockCtx}}
	ntlmAuthn(nil, np, authCache, DefaultAuthOptions())

	authCache.Set("N123", mockCtx, cache.DefaultExpiration)

	// Wait for eviction
	time.Sleep(5 * time.Millisecond)

	if !mockCtx.releaseCalled {
		t.Error("Expected SSPI context to be released upon cache eviction")
	}
}
