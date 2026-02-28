// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- mocks -------------------------------------------------------------------

// mockCertStoreBackend is a configurable fake certStoreBackend for unit tests.
type mockCertStoreBackend struct {
	getCertFn func(subject string, store CertStore) (*CertificateSource, error)
}

func (m *mockCertStoreBackend) GetCertificate(subject string, store CertStore) (*CertificateSource, error) {
	return m.getCertFn(subject, store)
}

// --- helpers -----------------------------------------------------------------

// newFakeCertSource creates an in-memory self-signed CertificateSource whose
// leaf certificate expires at notAfter. The wcs field is intentionally left
// nil; do not call Close() on the io.Closer returned by newCertificateFunc
// when using fake sources.
func newFakeCertSource(t *testing.T, notAfter time.Time) *CertificateSource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &CertificateSource{
		Certificate: tls.Certificate{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		},
	}
}

// --- CertStore constant tests ------------------------------------------------

// TestCertStoreConstants verifies the iota ordering of CertStore values.
func TestCertStoreConstants(t *testing.T) {
	if StoreLocalMachine != 0 {
		t.Errorf("StoreLocalMachine = %d, want 0", StoreLocalMachine)
	}
	if StoreCurrentUser != 1 {
		t.Errorf("StoreCurrentUser = %d, want 1", StoreCurrentUser)
	}
}

// --- CertificateSource.Close tests ------------------------------------------

// TestCertificateSource_Close_nilStore verifies that Close is a no-op when the
// source has no backing store.
func TestCertificateSource_Close_nilStore(t *testing.T) {
	src := &CertificateSource{}
	if err := src.Close(); err != nil {
		t.Errorf("Close() with nil store = %v, want nil", err)
	}
}

// TestCertificateSource_Close_callsStore verifies that Close delegates to the
// backing store and propagates its return value.
func TestCertificateSource_Close_callsStore(t *testing.T) {
	wantErr := fmt.Errorf("store close error")
	mock := &mockWinCertStore{closeFn: func() error { return wantErr }}
	src := &CertificateSource{wcs: mock}

	if err := src.Close(); err != wantErr {
		t.Errorf("Close() = %v, want %v", err, wantErr)
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close() call on store, got %d", mock.closeCalls)
	}
}

// --- certCloser.Close tests --------------------------------------------------

// TestCertCloser_Close_emptyCache verifies that calling Close on a certCloser
// whose cache has never been populated returns nil without panicking.
func TestCertCloser_Close_emptyCache(t *testing.T) {
	var cached atomic.Pointer[cachedCert]
	var mu sync.Mutex
	var retired []*CertificateSource
	var wg sync.WaitGroup
	c := &certCloser{cached: &cached, mu: &mu, retired: &retired, wg: &wg}
	if err := c.Close(); err != nil {
		t.Errorf("Close() on empty cache = %v, want nil", err)
	}
}

// TestCertCloser_Close_withCachedSource verifies that Close delegates to the
// source held in the cache and propagates its return value.
func TestCertCloser_Close_withCachedSource(t *testing.T) {
	mock := &mockWinCertStore{}
	src := &CertificateSource{wcs: mock}

	var cached atomic.Pointer[cachedCert]
	var mu sync.Mutex
	var retired []*CertificateSource
	var wg sync.WaitGroup
	cached.Store(&cachedCert{source: src, expiry: time.Now().Add(time.Hour)})
	c := &certCloser{cached: &cached, mu: &mu, retired: &retired, wg: &wg}

	if err := c.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	if mock.closeCalls != 1 {
		t.Errorf("expected 1 Close() call on store, got %d", mock.closeCalls)
	}
}

// --- newCertificateFunc unit tests -------------------------------------------

// TestNewCertificateFunc_hotPath verifies that when the cached certificate is
// well within the refresh threshold, the callback returns it immediately and
// no background refresh is triggered.
func TestNewCertificateFunc_hotPath(t *testing.T) {
	threshold := time.Hour
	cert := newFakeCertSource(t, time.Now().Add(24*time.Hour))

	var fetchCalls atomic.Int32
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			fetchCalls.Add(1)
			return cert, nil
		},
	}

	getCert, _, err := newCertificateFunc("test", StoreLocalMachine, threshold, 0, backend)
	if err != nil {
		t.Fatalf("newCertificateFunc: %v", err)
	}
	if n := fetchCalls.Load(); n != 1 {
		t.Fatalf("expected 1 initial fetch, got %d", n)
	}

	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("getCert: %v", err)
	}
	if got != &cert.Certificate {
		t.Error("getCert returned wrong certificate on hot path")
	}

	// Allow time for a spurious goroutine to start (it should not).
	time.Sleep(20 * time.Millisecond)
	if n := fetchCalls.Load(); n != 1 {
		t.Errorf("hot path: expected no background fetch, got %d total calls", n)
	}
}

// TestNewCertificateFunc_zeroThreshold verifies that a zero refreshThreshold
// never triggers a background refresh for a non-expired certificate — any
// non-negative time-until-expiry satisfies the >= 0 hot-path condition.
func TestNewCertificateFunc_zeroThreshold(t *testing.T) {
	cert := newFakeCertSource(t, time.Now().Add(time.Minute))

	var fetchCalls atomic.Int32
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			fetchCalls.Add(1)
			return cert, nil
		},
	}

	getCert, _, err := newCertificateFunc("test", StoreLocalMachine, 0, 0, backend)
	if err != nil {
		t.Fatalf("newCertificateFunc: %v", err)
	}

	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("getCert: %v", err)
	}
	if got != &cert.Certificate {
		t.Error("getCert returned wrong certificate")
	}

	time.Sleep(20 * time.Millisecond)
	if n := fetchCalls.Load(); n != 1 {
		t.Errorf("with threshold=0 and non-expired cert, expected 1 fetch, got %d", n)
	}
}

// TestNewCertificateFunc_refreshWindow verifies that when the cached cert is
// within the refresh threshold the callback still serves the current cert
// while triggering a background refresh, and that the new cert is served once
// the refresh completes.
func TestNewCertificateFunc_refreshWindow(t *testing.T) {
	threshold := time.Hour
	cert1 := newFakeCertSource(t, time.Now().Add(30*time.Minute)) // within window
	cert2 := newFakeCertSource(t, time.Now().Add(24*time.Hour))   // fresh replacement

	refreshDone := make(chan struct{})
	var fetchCalls atomic.Int32
	var once sync.Once
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			n := fetchCalls.Add(1)
			if n == 1 {
				return cert1, nil
			}
			// Use Once so that extra refresh attempts triggered by the retry loop
			// below cannot close an already-closed channel.
			once.Do(func() { close(refreshDone) })
			return cert2, nil
		},
	}

	getCert, _, err := newCertificateFunc("test", StoreLocalMachine, threshold, 0, backend)
	if err != nil {
		t.Fatalf("newCertificateFunc: %v", err)
	}

	// cert1 is in the refresh window: first call must return cert1 and start a
	// background refresh.
	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("getCert (first): %v", err)
	}
	if got != &cert1.Certificate {
		t.Error("first call should return cert1 while refresh runs")
	}

	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("background refresh did not complete in time")
	}

	// refreshDone fires when fetch() returns, but the goroutine still needs to
	// parse the new cert and atomically store it. Poll until cert2 is served.
	deadline := time.Now().Add(5 * time.Second)
	var got2 *tls.Certificate
	for time.Now().Before(deadline) {
		got2, err = getCert(nil)
		if err != nil {
			t.Fatalf("getCert (after refresh): %v", err)
		}
		if got2 == &cert2.Certificate {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got2 != &cert2.Certificate {
		t.Error("after refresh, getCert should return cert2")
	}
}

// TestNewCertificateFunc_refreshFails verifies that when the background refresh
// fetch returns an error, the previously cached certificate continues to be served.
func TestNewCertificateFunc_refreshFails(t *testing.T) {
	threshold := time.Hour
	cert1 := newFakeCertSource(t, time.Now().Add(30*time.Minute))

	refreshDone := make(chan struct{})
	var fetchCalls atomic.Int32
	var once sync.Once
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			n := fetchCalls.Add(1)
			if n == 1 {
				return cert1, nil
			}
			// Once protects against duplicate closes: cert1 stays within the
			// refresh window, so getCert may trigger additional retries.
			once.Do(func() { close(refreshDone) })
			return nil, fmt.Errorf("store unavailable")
		},
	}

	getCert, _, err := newCertificateFunc("test", StoreLocalMachine, threshold, 0, backend)
	if err != nil {
		t.Fatalf("newCertificateFunc: %v", err)
	}

	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("getCert (first): %v", err)
	}
	if got != &cert1.Certificate {
		t.Error("first call should return cert1")
	}

	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("background refresh goroutine did not complete in time")
	}

	time.Sleep(10 * time.Millisecond)

	got2, err := getCert(nil)
	if err != nil {
		t.Fatalf("getCert (after failed refresh): %v", err)
	}
	if got2 != &cert1.Certificate {
		t.Error("after failed refresh, getCert should still return cert1")
	}
}

// TestNewCertificateFunc_refreshBadDER verifies that when the background
// refresh fetch returns a source with unparseable DER bytes, the cached
// certificate is preserved and the bad source is closed without a panic.
func TestNewCertificateFunc_refreshBadDER(t *testing.T) {
	threshold := time.Hour
	cert1 := newFakeCertSource(t, time.Now().Add(30*time.Minute))
	badSource := &CertificateSource{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("not valid DER")},
		},
	}

	refreshDone := make(chan struct{})
	var fetchCalls atomic.Int32
	var once sync.Once
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			n := fetchCalls.Add(1)
			if n == 1 {
				return cert1, nil
			}
			once.Do(func() { close(refreshDone) })
			return badSource, nil
		},
	}

	getCert, _, err := newCertificateFunc("test", StoreLocalMachine, threshold, 0, backend)
	if err != nil {
		t.Fatalf("newCertificateFunc: %v", err)
	}

	getCert(nil) // triggers background refresh

	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("background refresh goroutine did not complete in time")
	}

	time.Sleep(10 * time.Millisecond)

	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("getCert after bad-DER refresh: %v", err)
	}
	if got != &cert1.Certificate {
		t.Error("after bad-DER refresh, getCert should still return cert1")
	}
}

// TestNewCertificateFunc_noDoubleRefresh verifies that concurrent calls within
// the refresh window spawn exactly one background refresh goroutine.
func TestNewCertificateFunc_noDoubleRefresh(t *testing.T) {
	threshold := time.Hour
	cert1 := newFakeCertSource(t, time.Now().Add(30*time.Minute))
	cert2 := newFakeCertSource(t, time.Now().Add(24*time.Hour))

	unblock := make(chan struct{})
	refreshDone := make(chan struct{})
	var fetchCalls atomic.Int32
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			n := fetchCalls.Add(1)
			if n == 1 {
				return cert1, nil
			}
			<-unblock // hold the background fetch until we're done firing concurrent calls
			defer close(refreshDone)
			return cert2, nil
		},
	}

	getCert, _, err := newCertificateFunc("test", StoreLocalMachine, threshold, time.Hour, backend)
	if err != nil {
		t.Fatalf("newCertificateFunc: %v", err)
	}

	const concurrentCalls = 20
	var wg sync.WaitGroup
	for range concurrentCalls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			getCert(nil)
		}()
	}
	wg.Wait()

	close(unblock) // let the single background fetch complete
	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("background refresh goroutine did not complete in time")
	}

	if n := fetchCalls.Load(); n != 2 {
		t.Errorf("expected 2 fetch calls (1 initial + 1 background), got %d", n)
	}
}

// TestNewCertificateFunc_initialFetchError verifies that an error from the
// initial fetch is returned immediately with nil callback and closer.
func TestNewCertificateFunc_initialFetchError(t *testing.T) {
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			return nil, fmt.Errorf("store error")
		},
	}
	getCert, closer, err := newCertificateFunc("test", StoreLocalMachine, time.Hour, 0, backend)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if getCert != nil {
		t.Error("getCert should be nil on initial fetch error")
	}
	if closer != nil {
		t.Error("closer should be nil on initial fetch error")
	}
}

// TestNewCertificateFunc_initialParseFails verifies that when the initial fetch
// returns a source with unparseable DER bytes, the error is surfaced and the
// source is closed without panicking.
func TestNewCertificateFunc_initialParseFails(t *testing.T) {
	bad := &CertificateSource{
		Certificate: tls.Certificate{
			Certificate: [][]byte{[]byte("not valid DER")},
		},
	}
	backend := &mockCertStoreBackend{
		getCertFn: func(_ string, _ CertStore) (*CertificateSource, error) {
			return bad, nil
		},
	}
	_, _, err := newCertificateFunc("test", StoreLocalMachine, time.Hour, 0, backend)
	if err == nil {
		t.Fatal("expected error for invalid DER, got nil")
	}
}
