// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows && integration

// Run these tests with: go test -tags integration ./internal/cert/...
//
// These tests call into the real Windows certificate store API and require
// no external server or special setup beyond a normal Windows environment.
// They are kept separate from the unit tests to avoid hitting OS APIs during
// regular go test runs.

package cert

import (
	"testing"
	"time"
)

// absentSubject is a certificate CN expected not to exist in any Windows
// certificate store on a test machine.
const absentSubject = "gwim-integration-test-cert-that-does-not-exist-xyz"

// TestGetWin32Cert exercises GetWin32Cert against both Windows certificate
// stores using a subject that is not present. It verifies that the function
// returns an error in all cases without panicking or leaking resources.
//
// The LocalMachine subtest does not assert on the error message because
// OpenWinCertStoreWithOptions may fail before CertByCommonName is reached on
// accounts without read access to the LocalMachine store, producing an error
// that does not mention the subject.
func TestGetWin32Cert(t *testing.T) {
	tests := []struct {
		name  string
		store CertStore
	}{
		{"LocalMachine", StoreLocalMachine},
		{"CurrentUser", StoreCurrentUser},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, err := GetWin32Cert(absentSubject, tt.store)
			if err == nil {
				src.Close()
				t.Fatalf("GetWin32Cert(%q): expected error for absent subject, got nil", absentSubject)
			}
		})
	}
}

// TestGetCertificateFunc verifies that GetCertificateFunc surfaces the
// initial-fetch error at call time and returns nil for both the callback and
// the io.Closer, so callers can abort startup without a nil-pointer risk.
func TestGetCertificateFunc(t *testing.T) {
	getCert, closer, err := GetCertificateFunc(absentSubject, StoreLocalMachine, 24*time.Hour)
	if err == nil {
		if closer != nil {
			closer.Close()
		}
		t.Fatalf("GetCertificateFunc(%q): expected error for absent subject, got nil", absentSubject)
	}
	if getCert != nil {
		t.Error("GetCertificateFunc: callback should be nil when initial fetch fails")
	}
	if closer != nil {
		t.Error("GetCertificateFunc: closer should be nil when initial fetch fails")
	}
}
