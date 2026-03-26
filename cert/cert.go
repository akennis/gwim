// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/certtostore"
)

// CertStore identifies which Windows certificate store to search.
type CertStore int

const (
	// StoreLocalMachine searches the LocalMachine certificate store.
	StoreLocalMachine CertStore = iota
	// StoreCurrentUser searches the CurrentUser certificate store.
	StoreCurrentUser
)

// RefreshThreshold is the duration before a certificate's expiry at which
// GetCertificateFunc will transparently fetch a fresh certificate from the store.
const RefreshThreshold = 7 * 24 * time.Hour

// CertificateSource holds a TLS certificate retrieved from the Windows store along
// with the underlying store handles required to keep the private key signer valid.
// Call Close when the certificate is no longer needed (e.g. on server shutdown).
type CertificateSource struct {
	// Certificate is the validated tls.Certificate, ready for use in tls.Config.
	Certificate tls.Certificate
	wcs         *certtostore.WinCertStore
}

// Close releases the Windows certificate store handles held by this source.
func (cs *CertificateSource) Close() error {
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
	fromCurrentUser := store == StoreCurrentUser
	storeName := "LocalMachine"
	if fromCurrentUser {
		storeName = "CurrentUser"
	}

	wcs, err := certtostore.OpenWinCertStoreWithOptions(certtostore.WinCertStoreOptions{
		CurrentUser: fromCurrentUser,
		StoreFlags:  certtostore.CertStoreReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open %s cert store: %w", storeName, err)
	}

	leaf, ctx, _, err := wcs.CertByCommonName(subject)
	if err != nil {
		wcs.Close()
		return nil, fmt.Errorf("certificate with subject %q not found in %s: %w", subject, storeName, err)
	}

	// Validate the certificate: checks expiry, EKU (ServerAuth), and chain integrity.
	// x509.Verify uses the Windows certificate verification API on Windows, which
	// resolves and validates the full issuer chain from the system store.
	chains, err := leaf.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		wcs.Close()
		return nil, fmt.Errorf("certificate %q in %s failed validation: %w", subject, storeName, err)
	}

	// Build the DER-encoded chain for tls.Certificate: leaf + any intermediates.
	// The root CA is excluded — clients are expected to have it in their trust store.
	chain := chains[0]
	// Exclude the root CA; for self-signed certs include at least the leaf.
	rawLen := max(len(chain)-1, 1)
	rawChain := make([][]byte, rawLen)
	for i := range rawLen {
		rawChain[i] = chain[i].Raw
	}

	// NOTE: wcs and ctx are intentionally kept open. The signer returned by
	// CertKey holds a reference to the Windows key provider, which requires
	// both the store handle and the cert context to remain alive for signing
	// operations. They are released when Close is called on the returned source.
	signer, err := wcs.CertKey(ctx)
	if err != nil {
		wcs.Close()
		return nil, fmt.Errorf("failed to acquire private key for %q in %s: %w", subject, storeName, err)
	}

	return &CertificateSource{
		Certificate: tls.Certificate{
			Certificate: rawChain,
			PrivateKey:  signer,
		},
		wcs: wcs,
	}, nil
}

// cachedCert pairs a CertificateSource with its parsed leaf expiry so that
// both values are always read and written together as a single atomic unit.
type cachedCert struct {
	source *CertificateSource
	expiry time.Time
}

// certCloser implements io.Closer and releases the currently-cached certificate
// source. It is intended to be called on server shutdown, after active
// connections have drained (e.g. after http.Server.Shutdown returns).
type certCloser struct {
	cached *atomic.Pointer[cachedCert]
}

func (c *certCloser) Close() error {
	if cc := c.cached.Load(); cc != nil {
		return cc.source.Close()
	}
	return nil
}

// GetCertificateFunc fetches the named certificate from the Windows store
// immediately at call time, returning an error if that initial fetch fails so
// that servers can abort startup before accepting any requests. On success it
// returns a tls.Config.GetCertificate callback that serves the cached
// certificate and transparently refreshes it when the certificate is within
// RefreshThreshold of expiry, enabling zero-downtime certificate rotation.
//
// The returned io.Closer releases the Windows store handles held by the
// currently-cached certificate. It should be called after the server has
// finished draining connections (e.g. after http.Server.Shutdown returns).
//
// The callback is safe for concurrent use. The hot path (cache hit) is
// lock-free: it performs a single atomic pointer load and a time comparison.
// The mutex is only acquired on the slow path when a refresh is needed, and
// double-checked locking prevents multiple goroutines from refreshing
// simultaneously. When a refresh fails, the cached (possibly stale) certificate
// is returned so that the server continues serving rather than failing abruptly.
func GetCertificateFunc(subject string, store CertStore) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error) {
	// Eagerly fetch the certificate now so that configuration errors (wrong
	// subject, missing cert, validation failure) are surfaced at startup rather
	// than on the first TLS handshake.
	initial, err := GetWin32Cert(subject, store)
	if err != nil {
		return nil, nil, err
	}
	leaf, _ := x509.ParseCertificate(initial.Certificate.Certificate[0])

	var (
		mu     sync.Mutex
		cached atomic.Pointer[cachedCert]
	)
	cached.Store(&cachedCert{source: initial, expiry: leaf.NotAfter})

	getCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Hot path: a single atomic pointer load — no lock required.
		if c := cached.Load(); c != nil && time.Until(c.expiry) >= RefreshThreshold {
			return &c.source.Certificate, nil
		}

		// Slow path: serialize refreshes to avoid a thundering herd.
		mu.Lock()
		defer mu.Unlock()

		// Re-check after acquiring the lock; another goroutine may have already
		// completed a refresh while this one was waiting.
		if c := cached.Load(); c != nil && time.Until(c.expiry) >= RefreshThreshold {
			return &c.source.Certificate, nil
		}

		fresh, err := GetWin32Cert(subject, store)
		if err != nil {
			if c := cached.Load(); c != nil {
				// Best-effort: return the stale cert rather than failing.
				return &c.source.Certificate, nil
			}
			return nil, err
		}

		// Parse the leaf once to cache its expiry. The cert bytes are guaranteed
		// valid here — GetWin32Cert already called x509.Verify on them.
		leaf, _ := x509.ParseCertificate(fresh.Certificate.Certificate[0])

		// Atomically publish the new cert and its expiry as a single unit, so
		// readers on the hot path can never observe a mismatched pair.
		// The previous source is not explicitly closed here because ongoing TLS
		// sessions may still be using its private key signer. The Windows store
		// handles it held will be released once the Go runtime garbage-collects
		// the old signer.
		cached.Store(&cachedCert{source: fresh, expiry: leaf.NotAfter})
		return &fresh.Certificate, nil
	}

	return getCert, &certCloser{cached: &cached}, nil
}
