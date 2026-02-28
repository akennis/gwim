// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package integration_tests

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()

	if *serverURL == "" {
		println("Error: -server-url flag is required for integration tests")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestAuthn(t *testing.T) {
	// Common tests
	t.Run("InitialUnauthorized", testAuth_InitialUnauthorized)
	t.Run("InvalidScheme", testAuth_InvalidScheme)

	switch *authMode {
	case "ntlm":
		t.Run("Success", testNTLM_Success)
		t.Run("FullSequence", testNTLM_FullSequence)
		t.Run("HalfOpen", testNTLM_HalfOpen)
		t.Run("Malformed", testNTLM_Malformed)
		t.Run("Type3First", testNTLM_Type3First)
		t.Run("ClientSendsType2", testNTLM_ClientSendsType2)
	case "kerberos":
		t.Run("Success", testKerberos_Success)
		t.Run("FullSequence", testKerberos_FullSequence)
		t.Run("HalfOpen", testKerberos_HalfOpen)
		t.Run("NegotiateMalformed", testNegotiate_Malformed)
		t.Run("KerberosMalformed", testKerberos_Malformed)
	default:
		t.Fatalf("Unknown auth-mode: %s", *authMode)
	}
}
