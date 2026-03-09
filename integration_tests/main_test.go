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
	case "kerberos":
		t.Run("Success", testKerberos_Success)
		t.Run("FullSequence", testKerberos_FullSequence)
		t.Run("NegotiateMalformed", testNegotiate_Malformed)
		t.Run("KerberosMalformed", testKerberos_Malformed)
	default:
		t.Fatalf("Unknown auth-mode: %s", *authMode)
	}
}
