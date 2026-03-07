package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexbrainman/sspi"
)

// mockKerberosServerContext implements kerberosServerContext
type mockKerberosServerContext struct {
	username string
	err      error
}

func (m *mockKerberosServerContext) GetUsername() (string, error) {
	return m.username, m.err
}

// mockKerberosProvider implements kerberosProvider
type mockKerberosProvider struct {
	context  *mockKerberosServerContext
	authDone bool
	err      error
}

func (m *mockKerberosProvider) NewServerContext(creds *sspi.Credentials, clientToken []byte) (kerberosServerContext, bool, []byte, error) {
	return m.context, m.authDone, nil, m.err
}

func TestKerberosAuthn(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func(r *http.Request) *http.Request
		authHeader     string
		mockProvider   *mockKerberosProvider
		expectedStatus int
		expectedUser   string
		expectWWWAuth  bool
	}{
		{
			name:       "Success",
			authHeader: "Negotiate " + base64.StdEncoding.EncodeToString([]byte("valid-token")),
			mockProvider: &mockKerberosProvider{
				context:  &mockKerberosServerContext{username: "TESTUSER@EXAMPLE.COM"},
				authDone: true,
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "testuser",
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
			name:           "WrongAuthType",
			authHeader:     "Basic dGVzdDp0ZXN0",
			expectedStatus: http.StatusUnauthorized,
			expectWWWAuth:  true,
		},
		{
			name:           "InvalidBase64Token",
			authHeader:     "Negotiate invalid-base64-!!!",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:       "AuthenticationError",
			authHeader: "Negotiate " + base64.StdEncoding.EncodeToString([]byte("token")),
			mockProvider: &mockKerberosProvider{
				err: fmt.Errorf("sspi error"),
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:       "AuthenticationIncomplete",
			authHeader: "Negotiate " + base64.StdEncoding.EncodeToString([]byte("token")),
			mockProvider: &mockKerberosProvider{
				authDone: false,
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:       "IdentityError",
			authHeader: "Negotiate " + base64.StdEncoding.EncodeToString([]byte("token")),
			mockProvider: &mockKerberosProvider{
				context:  &mockKerberosServerContext{err: fmt.Errorf("identity error")},
				authDone: true,
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := kerberosAuthn(nil, tt.mockProvider)
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
			if tt.authHeader != "" {
				req.Header.Set(AUTHORIZATION, tt.authHeader)
			}

			rr := httptest.NewRecorder()
			handler(nextHandler).ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectWWWAuth {
				if rr.Header().Get(WWW_AUTH) != NEGOTIATE {
					t.Errorf("Expected %s header %q, got %q", WWW_AUTH, NEGOTIATE, rr.Header().Get(WWW_AUTH))
				}
			}
		})
	}
}
