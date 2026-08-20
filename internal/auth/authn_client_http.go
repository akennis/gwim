// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/alexbrainman/sspi"
	spnego "github.com/alexbrainman/sspi/negotiate"
	"github.com/alexbrainman/sspi/ntlm"
)

// debugf emits a log line when the environment variable GWIM_DEBUG is set.
func debugf(format string, args ...any) {
	if os.Getenv("GWIM_DEBUG") != "" {
		log.Printf("[gwim] "+format, args...)
	}
}

// tokenKind returns a human-readable label for an authentication token so that
// debug output makes it obvious whether the transport is sending Kerberos,
// SPNEGO, or NTLM.
func tokenKind(token []byte) string {
	if len(token) == 0 {
		return "empty"
	}
	if len(token) >= 8 && string(token[:7]) == "NTLMSSP" {
		return fmt.Sprintf("NTLM(%d bytes)", len(token))
	}
	if token[0] == 0x60 {
		return fmt.Sprintf("SPNEGO(%d bytes)", len(token))
	}
	return fmt.Sprintf("unknown(0x%02x, %d bytes)", token[0], len(token))
}

// maxClientAuthLegs bounds the token exchanges in a single handshake. Kerberos
// completes in one leg and NTLM in two, so anything beyond this is a
// misbehaving server rather than a legitimate negotiation.
const maxClientAuthLegs = 4

// drainLimit caps how much of a discarded response body is read before the
// connection is returned to the pool.
const drainLimit = 64 << 10

// clientSecurityContext is the subset of the SSPI client contexts used by the
// transport, extracted so the handshake can be exercised without SSPI.
type clientSecurityContext interface {
	// Update consumes a token from the server and returns the next token to
	// send, or nil when the handshake produces nothing further.
	Update(token []byte) ([]byte, error)
	Release() error
}

// clientSecurityProvider starts one handshake and names the HTTP
// authentication scheme its tokens belong to.
type clientSecurityProvider interface {
	NewContext() (clientSecurityContext, []byte, error)
	Scheme() string
}

// --- SPNEGO (Kerberos) ---

type spnegoProvider struct {
	creds *sspi.Credentials
	spn   string
}

func (p *spnegoProvider) NewContext() (clientSecurityContext, []byte, error) {
	cc, token, err := spnego.NewClientContext(p.creds, p.spn)
	if err != nil {
		return nil, nil, err
	}
	return &spnegoContext{ClientContext: cc}, token, nil
}

func (p *spnegoProvider) Scheme() string { return negotiate }

// spnegoContext adapts the three-valued SPNEGO Update to the interface. The
// completion flag is dropped: the server's challenges, not the client's view
// of the handshake, decide whether another leg is sent.
type spnegoContext struct {
	*spnego.ClientContext
}

func (c *spnegoContext) Update(token []byte) ([]byte, error) {
	_, next, err := c.ClientContext.Update(token)
	return next, err
}

// --- NTLM with channel binding token (CBT) ---

// certCapture stores the raw DER of the TLS server certificate observed on the
// first response. The fallback provider reads it when building the NTLM
// AUTHENTICATE message so the channel binding token (CBT) can be included.
type certCapture struct {
	mu  sync.RWMutex
	raw []byte
}

func (c *certCapture) store(raw []byte) {
	c.mu.Lock()
	c.raw = raw
	c.mu.Unlock()
}

func (c *certCapture) load() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.raw
}

// certCapturingTransport wraps a base RoundTripper and records the TLS server
// certificate from every HTTPS response. It is transparent to the caller.
type certCapturingTransport struct {
	base    http.RoundTripper
	capture *certCapture
}

func (t *certCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		t.capture.store(resp.TLS.PeerCertificates[0].Raw)
	}
	return resp, nil
}

// ntlmCBTContext is an NTLM client security context that includes a channel
// binding token (CBT) in the AUTHENTICATE message. It calls the raw
// sspi.Context.Update directly so it can supply a SECBUFFER_CHANNEL_BINDINGS
// input buffer — a feature the ntlm package's ClientContext.Update does not
// expose. This satisfies IIS Extended Protection for Authentication (EPA).
type ntlmCBTContext struct {
	sctxt *sspi.Context
	cbt   []byte
}

// newNTLMCBTContext creates an NTLM client context and returns the initial
// NEGOTIATE token. cbt is the pre-computed GSS channel bindings blob; pass
// nil for plain-HTTP endpoints where there is no TLS session to bind to.
func newNTLMCBTContext(creds *sspi.Credentials, cbt []byte) (*ntlmCBTContext, []byte, error) {
	buf := make([]byte, ntlm.PackageInfo.MaxToken)
	c := sspi.NewClientContext(creds, sspi.ISC_REQ_CONNECTION)

	var outBuf [1]sspi.SecBuffer
	outBuf[0].Set(sspi.SECBUFFER_TOKEN, buf)
	outBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &outBuf[0],
	}
	var inBuf [1]sspi.SecBuffer
	inBuf[0].Set(sspi.SECBUFFER_TOKEN, nil)
	inBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &inBuf[0],
	}

	ret := c.Update(nil, outBufs, inBufs)
	switch ret {
	case sspi.SEC_I_CONTINUE_NEEDED:
		// expected: NTLM requires a second round-trip for the challenge
	case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
		if r := sspi.CompleteAuthToken(c.Handle, outBufs); r != sspi.SEC_E_OK {
			c.Release()
			return nil, nil, r
		}
	default:
		c.Release()
		return nil, nil, fmt.Errorf("NTLM negotiate failed: %w", ret)
	}
	return &ntlmCBTContext{sctxt: c, cbt: cbt}, outBuf[0].Bytes(), nil
}

// Update processes the server NTLM challenge and produces the AUTHENTICATE
// token. When a CBT was set on creation, it is supplied as a second
// SECBUFFER_CHANNEL_BINDINGS input buffer so that IIS EPA validation passes.
func (c *ntlmCBTContext) Update(challenge []byte) ([]byte, error) {
	buf := make([]byte, ntlm.PackageInfo.MaxToken)

	var inBuf [2]sspi.SecBuffer
	inBuf[0].Set(sspi.SECBUFFER_TOKEN, challenge)
	inBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &inBuf[0],
	}
	if len(c.cbt) > 0 {
		inBuf[1].Set(sspi.SECBUFFER_CHANNEL_BINDINGS, c.cbt)
		inBufs.BuffersCount = 2
	}

	var outBuf [1]sspi.SecBuffer
	outBuf[0].Set(sspi.SECBUFFER_TOKEN, buf)
	outBufs := &sspi.SecBufferDesc{
		Version:      sspi.SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      &outBuf[0],
	}

	ret := c.sctxt.Update(nil, outBufs, inBufs)
	switch ret {
	case sspi.SEC_E_OK, sspi.SEC_I_CONTINUE_NEEDED:
		return outBuf[0].Bytes(), nil
	case sspi.SEC_I_COMPLETE_NEEDED, sspi.SEC_I_COMPLETE_AND_CONTINUE:
		if r := sspi.CompleteAuthToken(c.sctxt.Handle, outBufs); r != sspi.SEC_E_OK {
			return nil, r
		}
		return outBuf[0].Bytes(), nil
	default:
		return nil, fmt.Errorf("NTLM authenticate failed: %w", ret)
	}
}

func (c *ntlmCBTContext) Release() error {
	return c.sctxt.Release()
}

// ntlmWithCBTProvider creates NTLM contexts that include a channel binding
// token derived from the TLS certificate captured by certCapturingTransport.
// Tokens are sent under the Negotiate scheme: IIS's AcceptSecurityContext
// recognises the NTLMSSP signature regardless of which HTTP scheme header
// carries them.
type ntlmWithCBTProvider struct {
	creds   *sspi.Credentials
	capture *certCapture
}

func (p *ntlmWithCBTProvider) NewContext() (clientSecurityContext, []byte, error) {
	var cbt []byte
	if raw := p.capture.load(); len(raw) > 0 {
		var err error
		cbt, err = createChannelBindings(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create channel bindings for NTLM fallback: %w", err)
		}
		debugf("fallback: computed CBT from TLS cert (%d bytes raw cert → %d bytes CBT)", len(raw), len(cbt))
	} else {
		debugf("fallback: no TLS cert captured — NTLM will proceed without CBT (plain HTTP or cert not yet seen)")
	}
	return newNTLMCBTContext(p.creds, cbt)
}

func (p *ntlmWithCBTProvider) Scheme() string { return negotiate }

// --- Transport ---

// ClientTransport is an http.RoundTripper that authenticates each outbound
// request using the calling process's own Windows credentials via Kerberos
// (SPNEGO). When a fallback provider is configured it retries with NTLM
// if the server returns a bare 401.
type ClientTransport struct {
	base             http.RoundTripper
	creds            *sspi.Credentials
	fallbackCreds    *sspi.Credentials // non-nil when a fallback provider is configured
	provider         clientSecurityProvider
	fallbackProvider clientSecurityProvider
	target           string // SPN for errors
	verifyMutual     bool
	serialize        bool
	mu               sync.Mutex
}

// NewNegotiateTransport acquires the current process's credentials and returns
// a transport that authenticates to spn with Kerberos (SPNEGO). When
// ntlmFallback is true, a bare 401 from the server triggers a second attempt
// using NTLM tokens sent under the Negotiate scheme — IIS's SSPI layer
// recognises the NTLMSSP signature regardless of the HTTP scheme header. For
// HTTPS endpoints, the TLS server certificate is captured automatically and
// included as a channel binding token so that IIS Extended Protection for
// Authentication (EPA) validation succeeds. Pass nil for base to use
// http.DefaultTransport.
func NewNegotiateTransport(spn string, ntlmFallback bool, base http.RoundTripper) (*ClientTransport, error) {
	if spn == "" {
		return nil, fmt.Errorf("gwim: Negotiate SPN is required")
	}
	creds, err := spnego.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire credentials for outbound Negotiate: %w", err)
	}
	if base == nil {
		base = http.DefaultTransport
	}
	ct := &ClientTransport{
		base:         base,
		creds:        creds,
		provider:     &spnegoProvider{creds: creds, spn: spn},
		target:       spn,
		verifyMutual: true,
	}
	if ntlmFallback {
		ntlmCreds, err := ntlm.AcquireCurrentUserCredentials()
		if err != nil {
			_ = creds.Release()
			return nil, fmt.Errorf("failed to acquire NTLM credentials for fallback: %w", err)
		}
		// Wrap the base transport to capture the TLS server certificate.
		// certCapturingTransport records the cert from the first HTTPS response;
		// ntlmWithCBTProvider reads it when creating the AUTHENTICATE message.
		capture := &certCapture{}
		ct.base = &certCapturingTransport{base: ct.base, capture: capture}
		ct.fallbackCreds = ntlmCreds
		ct.fallbackProvider = &ntlmWithCBTProvider{creds: ntlmCreds, capture: capture}
		// Requests are serialised because NTLM binds its handshake state to
		// the underlying TCP connection.
		ct.serialize = true
	}
	return ct, nil
}

// Close releases the Windows SSPI credentials held by the transport.
// Call this on shutdown, after the last request has completed.
func (t *ClientTransport) Close() error {
	var err error
	if t.creds != nil {
		err = t.creds.Release()
	}
	if t.fallbackCreds != nil {
		if err2 := t.fallbackCreds.Release(); err == nil {
			err = err2
		}
	}
	return err
}

// RoundTrip performs the handshake and returns the response to the
// authenticated request. A bare 401 triggers the fallback provider when one
// is configured; otherwise it is returned to the caller as-is.
func (t *ClientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.serialize {
		t.mu.Lock()
		defer t.mu.Unlock()
	}

	debugf("primary: starting %s handshake for %q", t.provider.Scheme(), t.target)
	resp, err := t.runHandshake(req, t.provider, t.verifyMutual, false)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized && t.fallbackProvider != nil {
		debugf("primary: bare 401 — triggering %s fallback", t.fallbackProvider.Scheme())
		drainAndClose(resp)
		return t.runHandshake(req, t.fallbackProvider, false, true)
	}
	return resp, nil
}

// runHandshake drives the multi-leg token exchange for a single provider.
// bodyConsumed signals that the original request body has already been sent
// on a previous attempt and must be replayed via GetBody from the first leg.
func (t *ClientTransport) runHandshake(req *http.Request, provider clientSecurityProvider, verifyMutual, bodyConsumed bool) (*http.Response, error) {
	scheme := provider.Scheme()
	secCtx, token, err := provider.NewContext()
	if err != nil {
		closeBody(req)
		return nil, fmt.Errorf("failed to start %s context for %q: %w", scheme, t.target, err)
	}
	debugf("handshake(%s): initial token %s", scheme, tokenKind(token))
	defer secCtx.Release() //nolint:errcheck

	for leg := 0; leg < maxClientAuthLegs; leg++ {
		attempt, err := clientAuthAttempt(req, scheme, token, leg, bodyConsumed)
		if err != nil {
			closeBody(req)
			return nil, err
		}

		debugf("handshake(%s): leg %d → sending %s token", scheme, leg, tokenKind(token))
		resp, err := t.base.RoundTrip(attempt)
		if err != nil {
			return nil, err
		}
		debugf("handshake(%s): leg %d ← %s  WWW-Authenticate: %q", scheme, leg, resp.Status, resp.Header.Get(wwwAuthenticate))

		serverToken, err := clientAuthChallenge(resp, scheme)
		if err != nil {
			drainAndClose(resp)
			return nil, err
		}
		debugf("handshake(%s): leg %d server token %s", scheme, leg, tokenKind(serverToken))

		if resp.StatusCode != http.StatusUnauthorized {
			// The exchange is over. When SPNEGO includes a mutual
			// authentication token, feeding it to the context proves the
			// server holds the SPN's key — a failure there means the response
			// cannot be trusted and must not reach the caller.
			if verifyMutual && len(serverToken) > 0 {
				if _, err := secCtx.Update(serverToken); err != nil {
					drainAndClose(resp)
					return nil, fmt.Errorf("mutual authentication with %q failed: %w", t.target, err)
				}
			}
			return resp, nil
		}

		if len(serverToken) == 0 {
			// Rejected without a continuation token: there is nothing left to
			// negotiate, so hand the 401 back for the caller (or fallback) to handle.
			return resp, nil
		}

		// Draining rather than abandoning the body returns the connection to
		// the pool, which is what lets the next leg reuse it.
		drainAndClose(resp)
		next, err := secCtx.Update(serverToken)
		if err != nil {
			closeBody(req)
			return nil, fmt.Errorf("%s handshake with %q failed: %w", scheme, t.target, err)
		}
		if len(next) == 0 {
			closeBody(req)
			return nil, fmt.Errorf("%s handshake with %q stalled: the server challenged again but the context produced no token", scheme, t.target)
		}
		token = next
		bodyConsumed = true
	}

	closeBody(req)
	return nil, fmt.Errorf("%s handshake with %q did not complete within %d legs", scheme, t.target, maxClientAuthLegs)
}

// clientAuthAttempt clones req with the Authorization header set to token.
// Continuation legs and fallback attempts re-read the body via GetBody, since
// a previous send has already consumed it.
func clientAuthAttempt(req *http.Request, scheme string, token []byte, leg int, bodyConsumed bool) (*http.Request, error) {
	attempt := req.Clone(req.Context())
	if req.Body != nil && (leg > 0 || bodyConsumed) {
		if req.GetBody == nil {
			return nil, fmt.Errorf("gwim: %s continuation requires a replayable request body - build the request with http.NewRequest and a *bytes.Reader, *bytes.Buffer or *strings.Reader", scheme)
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("failed to replay request body for %s continuation: %w", scheme, err)
		}
		attempt.Body = body
	}
	attempt.Header.Set(authorization, scheme+" "+base64.StdEncoding.EncodeToString(token))
	return attempt, nil
}

// clientAuthChallenge returns the decoded token from a challenge for scheme,
// or nil when the response carries no token for it.
func clientAuthChallenge(resp *http.Response, scheme string) ([]byte, error) {
	prefix := scheme + " "
	for _, header := range resp.Header.Values(wwwAuthenticate) {
		header = strings.TrimSpace(header)
		if header == scheme {
			return nil, nil
		}
		if !strings.HasPrefix(header, prefix) {
			continue
		}
		token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
		if err != nil {
			return nil, fmt.Errorf("invalid %s token in %s header: %w", scheme, wwwAuthenticate, err)
		}
		return token, nil
	}
	return nil, nil
}

func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	_ = resp.Body.Close()
}

// closeBody satisfies the RoundTripper contract, which requires the request
// body to be closed on every path that does not hand it to the base transport.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
