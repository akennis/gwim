package integration_tests

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type TestServer struct {
	URL string
	cmd *exec.Cmd
}

func SpawnTestServer(useNTLM bool) (*TestServer, error) {
	// Build the test server if not already built
	binaryPath := filepath.Join(os.TempDir(), "gwim_testserver.exe")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/testserver/main.go")
	buildCmd.Dir = "." // assuming we are in integration_tests
	if out, err := buildCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to build testserver: %v: %s", err, string(out))
	}

	cmd := exec.Command(binaryPath, "--addr", "127.0.0.1:0", fmt.Sprintf("--use-ntlm=%v", useNTLM))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Read the address from stdout
	scanner := bufio.NewScanner(stdout)
	var url string
	if scanner.Scan() {
		line := scanner.Text()
		fmt.Sscanf(line, "Test server listening on %s", &url)
		if !strings.HasPrefix(url, "http://") {
			url = "http://" + url
		}
	} else {
		cmd.Process.Kill()
		return nil, fmt.Errorf("failed to get address from testserver")
	}

	return &TestServer{
		URL: url,
		cmd: cmd,
	}, nil
}

func (ts *TestServer) Close() {
	if ts.cmd != nil && ts.cmd.Process != nil {
		ts.cmd.Process.Kill()
	}
}
