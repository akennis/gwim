package integration_tests

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()

	// If server-url is default, we can't really run against nothing.
	// We'll let individual tests start their own servers if needed,
	// or assume the user has provided a URL.

	os.Exit(m.Run())
}

func TestNTLM_WithLocalServer(t *testing.T) {
	if *serverURL != "" {
		// Run against provided server
		t.Run("Success", TestNTLM_Success)
		t.Run("HalfOpen", TestNTLM_HalfOpen)
		t.Run("Malformed", TestNTLM_Malformed)
		return
	}

	ts, err := SpawnTestServer(true)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer ts.Close()

	// Override the serverURL flag just for this test
	oldURL := *serverURL
	*serverURL = ts.URL
	defer func() { *serverURL = oldURL }()

	t.Run("Success", TestNTLM_Success)
	t.Run("HalfOpen", TestNTLM_HalfOpen)
	t.Run("Malformed", TestNTLM_Malformed)
}
