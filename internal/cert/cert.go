// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package cert

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
)

// winCertStore abstracts the certtostore.WinCertStore operations used by
// GetWin32Cert, enabling unit tests to inject in-memory certificate lookups
// without requiring a real Windows certificate store.
//
// The cert context exchanged between CertByCommonName and CertKey is typed as
// any to keep *windows.CertContext out of the interface, limiting the
// Windows-specific type to the adapter implementation below.
type winCertStore interface {
	CertByCommonName(cn string) (*x509.Certificate, any, [][]*x509.Certificate, error)
	CertKey(ctx any) (crypto.Signer, error)
	Close() error
}

// winCertStoreAdapter adapts *certtostore.WinCertStore to the winCertStore
// interface, handling the *windows.CertContext type conversion internally.
type winCertStoreAdapter struct {
	wcs *certtostore.WinCertStore
}

func (a *winCertStoreAdapter) CertByCommonName(cn string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
	return a.wcs.CertByCommonName(cn)
}

func (a *winCertStoreAdapter) CertKey(ctx any) (crypto.Signer, error) {
	certCtx, _ := ctx.(*windows.CertContext)
	return a.wcs.CertKey(certCtx)
}

func (a *winCertStoreAdapter) Close() error {
	return a.wcs.Close()
}

// storeOpener is the function signature for opening a Windows certificate
// store. The indirection allows unit tests to supply a mock store.
type storeOpener func(certtostore.WinCertStoreOptions) (winCertStore, error)

// certVerifier abstracts x509.Certificate.Verify, enabling unit tests to
// control the validated chain without hitting the Windows CryptoAPI.
type certVerifier func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)

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
	return getWin32CertWith(subject, store,
		func(opts certtostore.WinCertStoreOptions) (winCertStore, error) {
			wcs, err := certtostore.OpenWinCertStoreWithOptions(opts)
			if err != nil {
				return nil, err
			}
			return &winCertStoreAdapter{wcs}, nil
		},
		func(leaf *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
			return leaf.Verify(opts)
		},
	)
}

// getWin32CertWith is the testable core of GetWin32Cert. It accepts a
// storeOpener and certVerifier so that unit tests can inject in-memory
// certificate stores and chains without requiring a real Windows environment.
func getWin32CertWith(subject string, store CertStore, open storeOpener, verify certVerifier) (*CertificateSource, error) {
	fromCurrentUser := store == StoreCurrentUser
	storeName := "LocalMachine"
	if fromCurrentUser {
		storeName = "CurrentUser"
	}

	wcs, err := open(certtostore.WinCertStoreOptions{
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
	chains, err := verify(leaf, x509.VerifyOptions{
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

// certFetcher is the signature of the function used to retrieve a certificate
// from a store. The indirection allows unit tests to supply in-memory
// certificates without requiring a real Windows certificate store.
type certFetcher func(subject string, store CertStore) (*CertificateSource, error)

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
// Only one refresh goroutine runs at a time; subsequent requests within the
// same window are served from the cache immediately.
//
// The returned io.Closer releases the Windows store handles held by the
// currently-cached certificate. It should be called after the server has
// finished draining connections (e.g. after http.Server.Shutdown returns).
//
// The callback is safe for concurrent use. Both the hot path (cache hit) and
// the refresh-pending path perform only atomic pointer loads — no mutex is
// ever held on the request path.
func GetCertificateFunc(subject string, store CertStore, refreshThreshold time.Duration) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error) {
	return newCertificateFunc(subject, store, refreshThreshold, GetWin32Cert)
}

// newCertificateFunc is the testable core of GetCertificateFunc. It accepts a
// certFetcher so that unit tests can inject in-memory certificates.
func newCertificateFunc(subject string, store CertStore, refreshThreshold time.Duration, fetch certFetcher) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error) {
	// Eagerly fetch the certificate now so that configuration errors (wrong
	// subject, missing cert, validation failure) are surfaced at startup rather
	// than on the first TLS handshake.
	initial, err := fetch(subject, store)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(initial.Certificate.Certificate[0])
	if err != nil {
		initial.Close()
		return nil, nil, fmt.Errorf("cert: failed to parse leaf for %q: %w", subject, err)
	}

	var (
		cached     atomic.Pointer[cachedCert]
		refreshing atomic.Bool
	)
	cached.Store(&cachedCert{source: initial, expiry: leaf.NotAfter})

	getCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := cached.Load()

		// Hot path: cert is fresh — return immediately without any synchronisation.
		if c != nil && time.Until(c.expiry) >= refreshThreshold {
			return &c.source.Certificate, nil
		}

		// Within the refresh window: fire a background refresh if one is not
		// already running, then return the current cert without blocking.
		if refreshing.CompareAndSwap(false, true) {
			go func() {
				defer refreshing.Store(false)

				fresh, err := fetch(subject, store)
				if err != nil {
					// Keep serving the cached cert; the next request will retry.
					return
				}

				// Parse the leaf once to cache its expiry. The cert bytes are
				// guaranteed valid — GetWin32Cert already called x509.Verify.
				freshLeaf, err := x509.ParseCertificate(fresh.Certificate.Certificate[0])
				if err != nil {
					// Keep serving the cached cert; the next request will retry.
					fresh.Close()
					return
				}

				// Atomically publish the new cert and expiry as a single unit so
				// that readers on the hot path never observe a mismatched pair.
				// The previous source is not explicitly closed here because ongoing
				// TLS sessions may still hold a reference to its private key signer;
				// the Windows store handles will be released by the GC once the old
				// signer is no longer reachable.
				cached.Store(&cachedCert{source: fresh, expiry: freshLeaf.NotAfter})
			}()
		}

		// Serve the current cert (may be near expiry) while the refresh runs.
		if c != nil {
			return &c.source.Certificate, nil
		}
		return nil, fmt.Errorf("cert: no certificate available for %q", subject)
	}

	return getCert, &certCloser{cached: &cached}, nil
}
