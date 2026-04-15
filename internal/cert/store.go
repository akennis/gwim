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

	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
)

// certStoreBackend retrieves a validated, TLS-ready certificate from a backing
// store. The returned CertificateSource must be closed by the caller when no
// longer needed.
type certStoreBackend interface {
	GetCertificate(subject string, store CertStore) (*CertificateSource, error)
}

// winCertStore abstracts the certtostore.WinCertStore operations used by
// win32CertStoreBackend, enabling unit tests to inject in-memory certificate
// lookups without requiring a real Windows certificate store.
//
// The cert context exchanged between CertByCommonName and CertKey is typed as
// any to keep *windows.CertContext out of the interface, limiting the
// Windows-specific type to win32CertStore below.
type winCertStore interface {
	CertByCommonName(cn string) (*x509.Certificate, any, [][]*x509.Certificate, error)
	CertKey(ctx any) (crypto.Signer, error)
	Close() error
}

// win32CertStore adapts *certtostore.WinCertStore to the winCertStore
// interface, handling the *windows.CertContext type conversion internally.
type win32CertStore struct {
	wcs     *certtostore.WinCertStore
	certCtx *windows.CertContext
}

func (s *win32CertStore) CertByCommonName(cn string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
	cert, ctx, chains, err := s.wcs.CertByCommonName(cn)
	if err != nil && ctx != nil {
		certtostore.FreeCertContext(ctx)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	s.certCtx = ctx
	return cert, ctx, chains, nil
}

func (s *win32CertStore) CertKey(ctx any) (crypto.Signer, error) {
	certCtx, _ := ctx.(*windows.CertContext)
	return s.wcs.CertKey(certCtx)
}

func (s *win32CertStore) Close() error {
	if s.certCtx != nil {
		certtostore.FreeCertContext(s.certCtx)
	}
	return s.wcs.Close()
}

// storeOpener is the function signature for opening a Windows certificate
// store. The indirection allows unit tests to supply a mock store.
type storeOpener func(certtostore.WinCertStoreOptions) (winCertStore, error)

// certVerifier abstracts x509.Certificate.Verify, enabling unit tests to
// control the validated chain without hitting the Windows CryptoAPI.
type certVerifier func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)

// win32CertStoreBackend implements certStoreBackend using the Windows
// certificate store via certtostore. openFn and verifyFn are nil in production;
// tests set them to inject mock stores and chains.
type win32CertStoreBackend struct {
	openFn   storeOpener
	verifyFn certVerifier
}

func (b *win32CertStoreBackend) open(opts certtostore.WinCertStoreOptions) (winCertStore, error) {
	if b.openFn != nil {
		return b.openFn(opts)
	}
	wcs, err := certtostore.OpenWinCertStoreWithOptions(opts)
	if err != nil {
		return nil, err
	}
	return &win32CertStore{wcs: wcs}, nil
}

func (b *win32CertStoreBackend) verify(leaf *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if b.verifyFn != nil {
		return b.verifyFn(leaf, opts)
	}
	return leaf.Verify(opts)
}

// GetCertificate retrieves the certificate with the given subject from the
// Windows certificate store identified by store, validates it, and returns a
// CertificateSource. The caller must call Close on the returned source.
func (b *win32CertStoreBackend) GetCertificate(subject string, store CertStore) (*CertificateSource, error) {
	fromCurrentUser := store == StoreCurrentUser
	storeName := "LocalMachine"
	if fromCurrentUser {
		storeName = "CurrentUser"
	}

	wcs, err := b.open(certtostore.WinCertStoreOptions{
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
	chains, err := b.verify(leaf, x509.VerifyOptions{
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
