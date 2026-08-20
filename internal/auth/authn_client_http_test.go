// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// mockSecurityContext implements clientSecurityContext. Each call to Update
// consumes one scripted step.
type mockSecurityContext struct {
	steps     []mockSecurityStep
	updates   [][]byte
	released  bool
	stepIndex int
}

type mockSecurityStep struct {
	token []byte
	err   error
}

func (m *mockSecurityContext) Update(token []byte) ([]byte, error) {
	m.updates = append(m.updates, token)
	if m.stepIndex >= len(m.steps) {
		return nil, fmt.Errorf("unexpected Update call %d", m.stepIndex+1)
	}
	step := m.steps[m.stepIndex]
	m.stepIndex++
	return step.token, step.err
}

func (m *mockSecurityContext) Release() error {
	m.released = true
	return nil
}

// mockSecurityProvider implements clientSecurityProvider.
type mockSecurityProvider struct {
	context *mockSecurityContext
	token   []byte
	err     error
	scheme  string
	starts  atomic.Int32
}

func (m *mockSecurityProvider) NewContext() (clientSecurityContext, []byte, error) {
	m.starts.Add(1)
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.context, m.token, nil
}

func (m *mockSecurityProvider) Scheme() string {
	if m.scheme == "" {
		return negotiate
	}
	return m.scheme
}

func schemeHeader(scheme, token string) string {
	return scheme + " " + base64.StdEncoding.EncodeToString([]byte(token))
}

func newMockTransport(base http.RoundTripper, provider *mockSecurityProvider, verifyMutual bool) *ClientTransport {
	return &ClientTransport{
		base:         base,
		provider:     provider,
		target:       "HTTP/test.example.local",
		verifyMutual: verifyMutual,
	}
}

func newMockTransportWithFallback(base http.RoundTripper, primary, fallback *mockSecurityProvider) *ClientTransport {
	return &ClientTransport{
		base:             base,
		provider:         primary,
		fallbackProvider: fallback,
		target:           "HTTP/test.example.local",
		verifyMutual:     true,
		serialize:        true,
	}
}

func TestClientTransportSingleLeg(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get(authorization)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	provider := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("initial")}
	transport := newMockTransport(server.Client().Transport, provider, true)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if want := schemeHeader(negotiate, "initial"); gotAuth != want {
		t.Errorf("expected Authorization %q, got %q", want, gotAuth)
	}
	if req.Header.Get(authorization) != "" {
		t.Error("expected the caller's request to be left unmodified")
	}
}

func TestClientTransportContinuationReplaysBody(t *testing.T) {
	var auths []string
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get(authorization))
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		if len(auths) == 1 {
			w.Header().Set(wwwAuthenticate, schemeHeader(negotiate, "challenge"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	secCtx := &mockSecurityContext{steps: []mockSecurityStep{{token: []byte("second")}}}
	provider := &mockSecurityProvider{context: secCtx, token: []byte("initial")}
	transport := newMockTransport(server.Client().Transport, provider, true)

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if len(auths) != 2 {
		t.Fatalf("expected 2 legs, got %d", len(auths))
	}
	if want := schemeHeader(negotiate, "second"); auths[1] != want {
		t.Errorf("expected continuation Authorization %q, got %q", want, auths[1])
	}
	if bodies[0] != "payload" || bodies[1] != "payload" {
		t.Errorf("expected the body to be replayed on both legs, got %q and %q", bodies[0], bodies[1])
	}
	if len(secCtx.updates) != 1 || string(secCtx.updates[0]) != "challenge" {
		t.Errorf("expected the server challenge to be fed to the context, got %q", secCtx.updates)
	}
	if !secCtx.released {
		t.Error("expected the security context to be released")
	}
}

func TestClientTransportUnauthorizedWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(wwwAuthenticate, negotiate)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	provider := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("initial")}
	transport := newMockTransport(server.Client().Transport, provider, true)

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected the 401 to be returned, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestClientTransportMutualAuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(wwwAuthenticate, schemeHeader(negotiate, "server-token"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	secCtx := &mockSecurityContext{steps: []mockSecurityStep{{err: fmt.Errorf("bad server token")}}}
	provider := &mockSecurityProvider{context: secCtx, token: []byte("initial")}
	transport := newMockTransport(server.Client().Transport, provider, true)

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error when mutual authentication fails")
	}
	if !strings.Contains(err.Error(), "mutual authentication") {
		t.Errorf("expected a mutual authentication error, got %v", err)
	}
}

func TestClientTransportNonReplayableBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set(wwwAuthenticate, schemeHeader(negotiate, "challenge"))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	secCtx := &mockSecurityContext{steps: []mockSecurityStep{{token: []byte("second")}}}
	provider := &mockSecurityProvider{context: secCtx, token: []byte("initial")}
	transport := newMockTransport(server.Client().Transport, provider, true)

	req, _ := http.NewRequest(http.MethodPost, server.URL, io.NopCloser(strings.NewReader("payload")))
	req.GetBody = nil
	resp, err := transport.RoundTrip(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error when the body cannot be replayed")
	}
	if !strings.Contains(err.Error(), "replayable request body") {
		t.Errorf("expected a replayable body error, got %v", err)
	}
}

func TestClientTransportLegLimit(t *testing.T) {
	var legs int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		legs++
		w.Header().Set(wwwAuthenticate, schemeHeader(negotiate, "challenge"))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	steps := make([]mockSecurityStep, maxClientAuthLegs)
	for i := range steps {
		steps[i] = mockSecurityStep{token: []byte("next")}
	}
	provider := &mockSecurityProvider{context: &mockSecurityContext{steps: steps}, token: []byte("initial")}
	transport := newMockTransport(server.Client().Transport, provider, true)

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error when the handshake never completes")
	}
	if legs != maxClientAuthLegs {
		t.Errorf("expected %d legs, got %d", maxClientAuthLegs, legs)
	}
}

// TestClientTransportFallbackOnBare401 verifies that a bare 401 (no
// continuation token) from the primary handshake triggers the fallback
// provider, and that the fallback's scheme appears on the retry.
func TestClientTransportFallbackOnBare401(t *testing.T) {
	const fallbackScheme = "Negotiate" // fallback is also Negotiate (NTLM-within-SPNEGO)
	var auths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get(authorization))
		if len(auths) == 1 {
			// Bare 401 — no continuation token — triggers fallback.
			w.Header().Set(wwwAuthenticate, negotiate)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	primary := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("kerberos-token")}
	fallback := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("ntlm-token"), scheme: fallbackScheme}
	transport := newMockTransportWithFallback(server.Client().Transport, primary, fallback)

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 after fallback, got %d", resp.StatusCode)
	}
	if len(auths) != 2 {
		t.Fatalf("expected 2 requests (primary + fallback), got %d", len(auths))
	}
	if want := schemeHeader(negotiate, "kerberos-token"); auths[0] != want {
		t.Errorf("expected primary Kerberos token first, got %q", auths[0])
	}
	if want := schemeHeader(fallbackScheme, "ntlm-token"); auths[1] != want {
		t.Errorf("expected fallback token second, got %q", auths[1])
	}
	if primary.starts.Load() != 1 {
		t.Errorf("expected primary to start once, got %d", primary.starts.Load())
	}
	if fallback.starts.Load() != 1 {
		t.Errorf("expected fallback to start once, got %d", fallback.starts.Load())
	}
}

// TestClientTransportFallbackNotTriggeredOn200 verifies that a successful
// primary response does not invoke the fallback provider.
func TestClientTransportFallbackNotTriggeredOn200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	primary := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("kerberos-token")}
	fallback := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("ntlm-token")}
	transport := newMockTransportWithFallback(server.Client().Transport, primary, fallback)

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if fallback.starts.Load() != 0 {
		t.Errorf("expected fallback not to be invoked, but it started %d time(s)", fallback.starts.Load())
	}
}

// TestClientTransportFallbackReplaysBody verifies that a POST request body is
// correctly replayed for the fallback attempt via GetBody.
func TestClientTransportFallbackReplaysBody(t *testing.T) {
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		if len(bodies) == 1 {
			w.Header().Set(wwwAuthenticate, negotiate)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	primary := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("kerberos-token")}
	fallback := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("ntlm-token")}
	transport := newMockTransportWithFallback(server.Client().Transport, primary, fallback)

	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 after fallback, got %d", resp.StatusCode)
	}
	if len(bodies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(bodies))
	}
	if bodies[0] != "payload" || bodies[1] != "payload" {
		t.Errorf("expected body replayed on both attempts, got %q and %q", bodies[0], bodies[1])
	}
}

// TestClientTransportFallbackSerializesRequests verifies that when a fallback
// provider is configured, concurrent requests are serialised (serialize=true),
// preventing interleaved NTLM handshakes on the same connection.
func TestClientTransportFallbackSerializesRequests(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := inFlight.Add(1)
		for {
			peak := maxInFlight.Load()
			if current <= peak || maxInFlight.CompareAndSwap(peak, current) {
				break
			}
		}
		defer inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	primary := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("kerberos-token")}
	fallback := &mockSecurityProvider{context: &mockSecurityContext{}, token: []byte("ntlm-token")}
	transport := newMockTransportWithFallback(server.Client().Transport, primary, fallback)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Errorf("RoundTrip returned error: %v", err)
				return
			}
			drainAndClose(resp)
		}()
	}
	wg.Wait()

	if peak := maxInFlight.Load(); peak != 1 {
		t.Errorf("expected requests to be serialised, saw %d in flight at once", peak)
	}
}

func TestClientAuthChallenge(t *testing.T) {
	tests := []struct {
		name      string
		scheme    string
		headers   []string
		expected  string
		expectErr bool
	}{
		{name: "NoHeader", scheme: negotiate},
		{name: "BareNegotiate", scheme: negotiate, headers: []string{negotiate}},
		{name: "OtherScheme", scheme: negotiate, headers: []string{"Basic realm=\"test\""}},
		{name: "Token", scheme: negotiate, headers: []string{schemeHeader(negotiate, "token")}, expected: "token"},
		{name: "SecondHeader", scheme: negotiate, headers: []string{"NTLM", schemeHeader(negotiate, "token")}, expected: "token"},
		{name: "InvalidBase64", scheme: negotiate, headers: []string{negotiateSpc + "not-base64!!"}, expectErr: true},
		{name: "NtlmToken", scheme: ntlmScheme, headers: []string{schemeHeader(ntlmScheme, "token")}, expected: "token"},
		{name: "NtlmIgnoresNegotiate", scheme: ntlmScheme, headers: []string{schemeHeader(negotiate, "token")}},
		{name: "NegotiateIgnoresNtlm", scheme: negotiate, headers: []string{schemeHeader(ntlmScheme, "token")}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			for _, h := range tc.headers {
				resp.Header.Add(wwwAuthenticate, h)
			}

			token, err := clientAuthChallenge(resp, tc.scheme)
			if tc.expectErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(token) != tc.expected {
				t.Errorf("expected token %q, got %q", tc.expected, token)
			}
		})
	}
}
