// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// CertStore identifies which Windows certificate store to search.
type CertStore int

const (
	// StoreLocalMachine searches the LocalMachine certificate store.
	StoreLocalMachine CertStore = iota
	// StoreCurrentUser searches the CurrentUser certificate store.
	StoreCurrentUser
)

// CertificateSource holds a TLS certificate retrieved from the Windows store along
// with the underlying store handles required to keep the private key signer valid.
// Call Close when the certificate is no longer needed (e.g. on server shutdown).
type CertificateSource struct {
	// Certificate is the validated tls.Certificate, ready for use in tls.Config.
	Certificate tls.Certificate
	wcs         winCertStore
}

// Close releases the Windows certificate store handles held by this source.
// It is a no-op if the source was not backed by a real store (e.g. in tests).
func (cs *CertificateSource) Close() error {
	if cs.wcs == nil {
		return nil
	}
	return cs.wcs.Close()
}

// GetWin32Cert retrieves a certificate from the Windows certificate store by
// Common Name and returns a CertificateSource.
//
// The certificate is validated before being returned: it must not be expired and
// must carry the ExtKeyUsageServerAuth extended key usage. The returned
// tls.Certificate includes the full chain (leaf + intermediates, no root).
//
// The caller must call Close on the returned CertificateSource when it is no
// longer needed (e.g. on server shutdown) to release Windows store handles.
//
// For servers that need zero-downtime certificate rotation, use GetCertificateFunc
// instead of calling GetWin32Cert once at startup.
func GetWin32Cert(subject string, store CertStore) (*CertificateSource, error) {
	return (&win32CertStoreBackend{}).GetCertificate(subject, store)
}

// cachedCert pairs a CertificateSource with its parsed leaf expiry so that
// both values are always read and written together as a single atomic unit.
type cachedCert struct {
	source *CertificateSource
	expiry time.Time
}

// certCloser implements io.Closer and releases all certificate sources: the
// currently-cached one and any that were rotated out during the server's
// lifetime. It is intended to be called on server shutdown, after active
// connections have drained (e.g. after http.Server.Shutdown returns).
type certCloser struct {
	cached  *atomic.Pointer[cachedCert]
	mu      *sync.Mutex
	retired *[]*CertificateSource
	wg      *sync.WaitGroup
}

func (c *certCloser) Close() error {
	// Block until all in-flight background refresh goroutines have finished.
	// Without this, a goroutine that completes its fetch after Close returns
	// would store a new CertificateSource into cached via cached.Swap, and
	// that source would never be closed, leaking the Windows store handle.
	c.wg.Wait()

	c.mu.Lock()
	retired := *c.retired
	c.mu.Unlock()

	var errs []error
	for _, old := range retired {
		if err := old.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if cc := c.cached.Load(); cc != nil {
		if err := cc.source.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// GetCertificateFunc fetches the named certificate from the Windows store
// immediately at call time, returning an error if that initial fetch fails so
// that servers can abort startup before accepting any requests. On success it
// returns a tls.Config.GetCertificate callback that serves the cached
// certificate and transparently refreshes it when the certificate is within
// refreshThreshold of expiry, enabling zero-downtime certificate rotation.
//
// refreshThreshold controls how far before expiry a background refresh is
// triggered. The refresh runs in a separate goroutine so that in-flight
// requests are never blocked waiting for the store: the cached certificate
// (stale but still valid) is served until the background fetch completes.
//
// retryInterval is the minimum time between refresh attempts. If the store is
// unavailable (e.g. the certificate has not yet been renewed), requests within
// the refresh window would otherwise trigger a new goroutine on every call.
// retryInterval prevents that by rate-limiting attempts: a new goroutine is
// only launched if at least retryInterval has elapsed since the last attempt.
// At most one refresh goroutine runs per interval even under concurrent load.
//
// The returned io.Closer releases the Windows store handles held by the
// currently-cached certificate. It should be called after the server has
// finished draining connections (e.g. after http.Server.Shutdown returns).
//
// The callback is safe for concurrent use. Both the hot path (cache hit) and
// the refresh-pending path perform only atomic loads — no mutex is ever held
// on the request path.
func GetCertificateFunc(subject string, store CertStore, refreshThreshold, retryInterval time.Duration) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error) {
	return newCertificateFunc(subject, store, refreshThreshold, retryInterval, &win32CertStoreBackend{})
}

// newCertificateFunc is the testable core of GetCertificateFunc. It accepts a
// certStoreBackend so that unit tests can inject in-memory certificates.
func newCertificateFunc(subject string, store CertStore, refreshThreshold, retryInterval time.Duration, backend certStoreBackend) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error) {
	// Eagerly fetch the certificate now so that configuration errors (wrong
	// subject, missing cert, validation failure) are surfaced at startup rather
	// than on the first TLS handshake.
	initial, err := backend.GetCertificate(subject, store)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(initial.Certificate.Certificate[0])
	if err != nil {
		initial.Close()
		return nil, nil, fmt.Errorf("cert: failed to parse leaf for %q: %w", subject, err)
	}

	var (
		cached      atomic.Pointer[cachedCert]
		lastAttempt atomic.Int64 // Unix nanoseconds of the last refresh attempt; 0 = never attempted
		retiredMu   sync.Mutex
		retired     []*CertificateSource
		refreshWg   sync.WaitGroup
	)
	cached.Store(&cachedCert{source: initial, expiry: leaf.NotAfter})

	getCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := cached.Load()

		// Hot path: cert is fresh — return immediately without any synchronisation.
		if c != nil && time.Until(c.expiry) >= refreshThreshold {
			return &c.source.Certificate, nil
		}

		// Within the refresh window: fire a background refresh if at least
		// retryInterval has elapsed since the last attempt. The CAS ensures at
		// most one goroutine is launched per interval even under concurrent load,
		// so a temporarily unavailable store does not cause a goroutine storm.
		now := time.Now().UnixNano()
		last := lastAttempt.Load()
		if now-last >= retryInterval.Nanoseconds() && lastAttempt.CompareAndSwap(last, now) {
			refreshWg.Add(1)
			go func() {
				defer refreshWg.Done()
				fresh, err := backend.GetCertificate(subject, store)
				if err != nil {
					// Keep serving the cached cert; the next interval will retry.
					return
				}

				// Parse the leaf once to cache its expiry. The cert bytes are
				// guaranteed valid — GetWin32Cert already called x509.Verify.
				freshLeaf, err := x509.ParseCertificate(fresh.Certificate.Certificate[0])
				if err != nil {
					// Keep serving the cached cert; the next interval will retry.
					fresh.Close()
					return
				}

				// Atomically publish the new cert. Swap captures the old source so
				// it can be released on shutdown once all connections have drained.
				// We do not close it here because in-flight TLS sessions may still
				// hold a reference to its private key signer.
				if old := cached.Swap(&cachedCert{source: fresh, expiry: freshLeaf.NotAfter}); old != nil {
					retiredMu.Lock()
					retired = append(retired, old.source)
					retiredMu.Unlock()
				}
			}()
		}

		// Serve the current cert (may be near expiry) while the refresh runs.
		if c != nil {
			return &c.source.Certificate, nil
		}
		return nil, fmt.Errorf("cert: no certificate available for %q", subject)
	}

	return getCert, &certCloser{cached: &cached, mu: &retiredMu, retired: &retired, wg: &refreshWg}, nil
}
