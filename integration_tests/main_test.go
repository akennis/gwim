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
	switch *authMode {
	case "ntlm":
		t.Run("Success", TestNTLM_Success)
		t.Run("HalfOpen", TestNTLM_HalfOpen)
		t.Run("Malformed", TestNTLM_Malformed)
	case "kerberos":
		t.Run("Success", TestKerberos_Success)
	default:
		t.Fatalf("Unknown auth-mode: %s", *authMode)
	}
}
