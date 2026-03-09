package integration_tests

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

var (
	serverURL = flag.String("server-url", "", "The URL of the example server to test against")
	authMode  = flag.String("auth-mode", "ntlm", "Authentication mode to test (ntlm or kerberos)")
)

func TestNTLM_Success(t *testing.T) {
	client := &http.Client{}

	// 1. Start NTLM handshake (Type 1)
	sspiClient, err := NewNTLMClient("", "", "")
	if err != nil {
		t.Fatalf("Failed to create NTLM client: %v", err)
	}
	defer sspiClient.Release()

	authHeader, _, err := sspiClient.GetAuthHeader("", nil)
	if err != nil {
		t.Fatalf("Failed to generate NTLM Type 1 token: %v", err)
	}

	req, _ := http.NewRequest("GET", *serverURL, nil)
	req.Header.Set("Authorization", authHeader)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send NTLM Type 1 token: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Errorf("Expected 401 for NTLM Type 2, got %d. Body: %s", resp.StatusCode, string(body))
		return
	}

	var type2Token64 string
	for _, h := range resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")] {
		if strings.HasPrefix(h, "NTLM ") {
			type2Token64 = h[5:]
			break
		}
	}
	// Drain and close
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if type2Token64 == "" {
		fmt.Fprintf(os.Stderr, "Client: Headers: %v\n", resp.Header)
		t.Fatal("Expected NTLM challenge in WWW-Authenticate header")
	}

	type2Token, err := base64.StdEncoding.DecodeString(type2Token64)
	if err != nil {
		t.Fatalf("Failed to decode NTLM Type 2 token: %v", err)
	}

	// 3. Complete NTLM handshake (Type 3)
	authHeader, authDone, err := sspiClient.GetAuthHeader("", type2Token)
	if err != nil {
		t.Fatalf("Failed to generate NTLM Type 3 token: %v", err)
	}
	if !authDone {
		t.Log("Warning: SSPI reported auth not done after Type 3 generation (expected for NTLM)")
	}

	req, _ = http.NewRequest("GET", *serverURL, nil)
	req.Header.Set("Authorization", authHeader)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send NTLM Type 3 token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected 200 OK after NTLM auth, got %d. Body: %s", resp.StatusCode, string(body))
	} else {
		t.Log("Successfully authenticated with NTLM")
	}
}

func TestNTLM_HalfOpen(t *testing.T) {
	client := &http.Client{}

	// Send Type 1 and then just stop. This tests that the server doesn't leak contexts or crash.
	sspiClient, _ := NewNTLMClient("", "", "")
	defer sspiClient.Release()

	authHeader, _, _ := sspiClient.GetAuthHeader("", nil)

	req, _ := http.NewRequest("GET", *serverURL, nil)
	req.Header.Set("Authorization", authHeader)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send NTLM Type 1 token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for NTLM Type 2, got %d", resp.StatusCode)
	}

	// We stop here. The server's cache should eventually evict the context.
}

func TestNTLM_Malformed(t *testing.T) {
	client := &http.Client{}

	req, _ := http.NewRequest("GET", *serverURL, nil)
	req.Header.Set("Authorization", "NTLM SGVsbG8gV29ybGQ=") // "Hello World" in base64, not a valid NTLM token
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send malformed NTLM token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 401 or 400 for malformed NTLM token, got %d", resp.StatusCode)
	}
}

func TestKerberos_Success(t *testing.T) {
	// Kerberos usually requires a proper environment and SPN.
	// This test might fail if the environment is not set up, but we implement it for completeness.
	sspiClient, err := NewKerberosClient()
	if err != nil {
		t.Skipf("Skipping Kerberos test: could not acquire credentials: %v", err)
	}
	defer sspiClient.Release()

	client := &http.Client{}

	// Get target from URL
	target := strings.TrimPrefix(*serverURL, "http://")
	target = strings.TrimPrefix(target, "https://")
	if idx := strings.Index(target, ":"); idx != -1 {
		target = target[:idx]
	}
	spn := "HTTP/" + target

	authHeader, authDone, err := sspiClient.GetAuthHeader(spn, nil)
	if err != nil {
		t.Skipf("Skipping Kerberos test: could not generate token (maybe no ticket or SPN incorrect): %v", err)
	}

	req, _ := http.NewRequest("GET", *serverURL, nil)
	req.Header.Set("Authorization", authHeader)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make Kerberos request: %v", err)
	}
	defer resp.Body.Close()

	if authDone && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected 200 OK after Kerberos auth, got %d. Body: %s", resp.StatusCode, string(body))
	} else if !authDone && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for multi-step Kerberos, got %d", resp.StatusCode)
		// Multi-step Kerberos would need another RoundTrip here, similar to NTLM.
	}
}
