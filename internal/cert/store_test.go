// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/certtostore"
)

// --- mocks -------------------------------------------------------------------

// mockWinCertStore is a configurable fake winCertStore for unit tests.
type mockWinCertStore struct {
	certByCommonNameFn func(cn string) (*x509.Certificate, any, [][]*x509.Certificate, error)
	certKeyFn          func(ctx any) (crypto.Signer, error)
	closeFn            func() error
	closeCalls         int
}

func (m *mockWinCertStore) CertByCommonName(cn string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
	return m.certByCommonNameFn(cn)
}

func (m *mockWinCertStore) CertKey(ctx any) (crypto.Signer, error) {
	if m.certKeyFn != nil {
		return m.certKeyFn(ctx)
	}
	return nil, nil
}

func (m *mockWinCertStore) Close() error {
	m.closeCalls++
	if m.closeFn != nil {
		return m.closeFn()
	}
	return nil
}

// --- helpers -----------------------------------------------------------------

// mockOpen returns a storeOpener that always returns the provided store.
func mockOpen(store winCertStore) storeOpener {
	return func(_ certtostore.WinCertStoreOptions) (winCertStore, error) {
		return store, nil
	}
}

// mockVerifyChain returns a certVerifier that reports success with the
// provided chain.
func mockVerifyChain(chain []*x509.Certificate) certVerifier {
	return func(_ *x509.Certificate, _ x509.VerifyOptions) ([][]*x509.Certificate, error) {
		return [][]*x509.Certificate{chain}, nil
	}
}

// newFakeX509Cert creates and parses a self-signed in-memory certificate
// expiring at notAfter, returning the *x509.Certificate for use in chain
// construction.
func newFakeX509Cert(t *testing.T, notAfter time.Time) *x509.Certificate {
	t.Helper()
	src := newFakeCertSource(t, notAfter)
	cert, err := x509.ParseCertificate(src.Certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse fake cert: %v", err)
	}
	return cert
}

// newFakeSigner returns a fresh *ecdsa.PrivateKey usable as a crypto.Signer
// in mock certKeyFn implementations.
func newFakeSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	return key
}

// --- win32CertStoreBackend unit tests ----------------------------------------

// TestWin32CertStoreBackend_storeOpenFails verifies that an opener failure is
// returned as a wrapped error that names the store.
func TestWin32CertStoreBackend_storeOpenFails(t *testing.T) {
	tests := []struct {
		name      string
		store     CertStore
		wantStore string
	}{
		{"LocalMachine", StoreLocalMachine, "LocalMachine"},
		{"CurrentUser", StoreCurrentUser, "CurrentUser"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			open := func(_ certtostore.WinCertStoreOptions) (winCertStore, error) {
				return nil, fmt.Errorf("access denied")
			}
			_, err := (&win32CertStoreBackend{openFn: open}).GetCertificate("subject", tt.store)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantStore) {
				t.Errorf("error %q should name the store %q", err, tt.wantStore)
			}
		})
	}
}

// TestWin32CertStoreBackend_certNotFound verifies that a CertByCommonName
// failure returns a subject-mentioning error and closes the store exactly once.
func TestWin32CertStoreBackend_certNotFound(t *testing.T) {
	mock := &mockWinCertStore{
		certByCommonNameFn: func(_ string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
			return nil, nil, nil, fmt.Errorf("cert not found")
		},
	}
	_, err := (&win32CertStoreBackend{openFn: mockOpen(mock)}).GetCertificate("mysubject", StoreLocalMachine)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "mysubject") {
		t.Errorf("error %q should mention subject", err)
	}
	if mock.closeCalls != 1 {
		t.Errorf("store Close() called %d times, want 1", mock.closeCalls)
	}
}

// TestWin32CertStoreBackend_verifyFails verifies that a verification failure
// returns an error mentioning "failed validation" and closes the store.
func TestWin32CertStoreBackend_verifyFails(t *testing.T) {
	leaf := newFakeX509Cert(t, time.Now().Add(24*time.Hour))
	mock := &mockWinCertStore{
		certByCommonNameFn: func(_ string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
			return leaf, nil, nil, nil
		},
	}
	verify := func(_ *x509.Certificate, _ x509.VerifyOptions) ([][]*x509.Certificate, error) {
		return nil, fmt.Errorf("certificate expired")
	}
	_, err := (&win32CertStoreBackend{openFn: mockOpen(mock), verifyFn: verify}).GetCertificate("mysubject", StoreLocalMachine)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed validation") {
		t.Errorf("error %q should mention failed validation", err)
	}
	if mock.closeCalls != 1 {
		t.Errorf("store Close() called %d times, want 1", mock.closeCalls)
	}
}

// TestWin32CertStoreBackend_certKeyFails verifies that a CertKey failure
// returns an error mentioning "private key" and closes the store.
func TestWin32CertStoreBackend_certKeyFails(t *testing.T) {
	leaf := newFakeX509Cert(t, time.Now().Add(24*time.Hour))
	mock := &mockWinCertStore{
		certByCommonNameFn: func(_ string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
			return leaf, nil, nil, nil
		},
		certKeyFn: func(_ any) (crypto.Signer, error) {
			return nil, fmt.Errorf("key not accessible")
		},
	}
	_, err := (&win32CertStoreBackend{openFn: mockOpen(mock), verifyFn: mockVerifyChain([]*x509.Certificate{leaf})}).GetCertificate("mysubject", StoreLocalMachine)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error %q should mention private key", err)
	}
	if mock.closeCalls != 1 {
		t.Errorf("store Close() called %d times, want 1", mock.closeCalls)
	}
}

// TestWin32CertStoreBackend_selfSigned verifies that for a self-signed
// certificate (chain length 1) the rawChain contains only the leaf and the
// store is not closed on success.
func TestWin32CertStoreBackend_selfSigned(t *testing.T) {
	leaf := newFakeX509Cert(t, time.Now().Add(24*time.Hour))
	signer := newFakeSigner(t)
	mock := &mockWinCertStore{
		certByCommonNameFn: func(_ string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
			return leaf, nil, nil, nil
		},
		certKeyFn: func(_ any) (crypto.Signer, error) { return signer, nil },
	}
	src, err := (&win32CertStoreBackend{openFn: mockOpen(mock), verifyFn: mockVerifyChain([]*x509.Certificate{leaf})}).GetCertificate("mysubject", StoreLocalMachine)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if n := len(src.Certificate.Certificate); n != 1 {
		t.Fatalf("rawChain length = %d, want 1", n)
	}
	if !bytes.Equal(src.Certificate.Certificate[0], leaf.Raw) {
		t.Error("rawChain[0] should be the leaf DER")
	}
	if src.Certificate.PrivateKey != signer {
		t.Error("PrivateKey should be the mock signer")
	}
	if mock.closeCalls != 0 {
		t.Errorf("store should not be closed on success, got %d Close() calls", mock.closeCalls)
	}
}

// TestWin32CertStoreBackend_withIntermediates verifies that a chain with
// intermediates includes the leaf and intermediates but excludes the root.
func TestWin32CertStoreBackend_withIntermediates(t *testing.T) {
	leaf := newFakeX509Cert(t, time.Now().Add(24*time.Hour))
	intermediate := newFakeX509Cert(t, time.Now().Add(365*24*time.Hour))
	root := newFakeX509Cert(t, time.Now().Add(10*365*24*time.Hour))
	signer := newFakeSigner(t)
	mock := &mockWinCertStore{
		certByCommonNameFn: func(_ string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
			return leaf, nil, nil, nil
		},
		certKeyFn: func(_ any) (crypto.Signer, error) { return signer, nil },
	}
	src, err := (&win32CertStoreBackend{openFn: mockOpen(mock), verifyFn: mockVerifyChain([]*x509.Certificate{leaf, intermediate, root})}).GetCertificate("mysubject", StoreLocalMachine)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if n := len(src.Certificate.Certificate); n != 2 {
		t.Fatalf("rawChain length = %d, want 2 (leaf + intermediate, no root)", n)
	}
	if !bytes.Equal(src.Certificate.Certificate[0], leaf.Raw) {
		t.Error("rawChain[0] should be the leaf DER")
	}
	if !bytes.Equal(src.Certificate.Certificate[1], intermediate.Raw) {
		t.Error("rawChain[1] should be the intermediate DER")
	}
}

// TestWin32CertStoreBackend_storeNameCurrentUser verifies that the CurrentUser
// store name appears in both the open-failure and cert-not-found error messages.
func TestWin32CertStoreBackend_storeNameCurrentUser(t *testing.T) {
	t.Run("openFails", func(t *testing.T) {
		open := func(_ certtostore.WinCertStoreOptions) (winCertStore, error) {
			return nil, fmt.Errorf("denied")
		}
		_, err := (&win32CertStoreBackend{openFn: open}).GetCertificate("sub", StoreCurrentUser)
		if !strings.Contains(err.Error(), "CurrentUser") {
			t.Errorf("error %q should mention CurrentUser", err)
		}
	})
	t.Run("certNotFound", func(t *testing.T) {
		mock := &mockWinCertStore{
			certByCommonNameFn: func(_ string) (*x509.Certificate, any, [][]*x509.Certificate, error) {
				return nil, nil, nil, fmt.Errorf("not found")
			},
		}
		_, err := (&win32CertStoreBackend{openFn: mockOpen(mock)}).GetCertificate("sub", StoreCurrentUser)
		if !strings.Contains(err.Error(), "CurrentUser") {
			t.Errorf("error %q should mention CurrentUser", err)
		}
	})
}
