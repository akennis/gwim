# gwim

`gwim` is a Go library that simplifies Windows Integrated Authentication (Kerberos and NTLM) for Go web servers.

## API

The `gwim` package provides the following functions:

- `NewSSPIHandler(next http.Handler, useNTLM bool) (http.Handler, error)`: Creates an authentication middleware that wraps an existing `http.Handler`.
- `ConfigureNTLM(server *http.Server)`: Configures an `http.Server` for NTLM authentication.
- `ConfigureTLS(server *http.Server, certSubject string) error`: Configures an `http.Server` with a TLS certificate from the Windows certificate store.
- `User(r *http.Request) (string, []string, bool)`: Extracts the authenticated user's username and group memberships from the request context.

## Usage

Here is an example of how to use `gwim` to create a secure web server:

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/akennis/gwim"
	"github.com/akennis/gwim/auth"
)

func main() {
	// CLI flags for configuration
	serverAddr := flag.String("server-addr", "", "The address the server will listen on")
	secureServerPort := flag.Int("secure-server-port", 0, "The port the secure server will listen on")
	certSubject := flag.String("cert-subject", "", "The subject of the certificate to use")
	ldapAddress := flag.String("ldap-address", "", "The address of the LDAP server")
	ldapUsersDN := flag.String("ldap-users-dn", "", "The DN for users in the LDAP server")
	ldapServiceAccountSPN := flag.String("ldap-service-account-spn", "", "The SPN for the service account in the LDAP server")
	flag.Parse()

	if *serverAddr == "" || *secureServerPort == 0 || *certSubject == "" || *ldapAddress == "" || *ldapUsersDN == "" || *ldapServiceAccountSPN == "" {
		flag.Usage()
		log.Fatal("All flags are required")
	}

	useNTLM := *serverAddr == "localhost"

	// Initialize router
	router := http.NewServeMux()
	router.HandleFunc("/", rootHandler)

	// --- Apply Middleware ---
	var handler http.Handler = router
	var err error
	if *ldapAddress != "" {
		handler = gwim.NewLdapGroupProvider(handler, *ldapAddress, *ldapUsersDN, *ldapServiceAccountSPN)
	}
	handler, err = gwim.NewSSPIHandler(handler, useNTLM)
	if err != nil {
		log.Fatalf("Failed to create SSPI handler: %v", err)
	}


	// Configure HTTPS server
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", *serverAddr, *secureServerPort),
		Handler: handler,
	}

	if useNTLM {
		gwim.ConfigureNTLM(srv)
	}

	if err := gwim.ConfigureTLS(srv, *certSubject); err != nil {
		log.Fatalf("Failed to configure TLS: %v", err)
	}

	log.Printf("Starting secure server on https://%s", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	username, ok := gwim.User(r)
	if !ok {
		// This should theoretically not be reached if middleware is correct
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	groups, _ := gwim.UserGroups(r)
	if len(groups) > 0 {
		fmt.Fprintf(w, "Hello, %s! Your LDAP groups are: %v", username, groups)
	} else {
		fmt.Fprintf(w, "Hello, %s! You have a valid session.", username)
	}
}
```

To run the secure Windows server example, you need to provide the following required flags:

```bash
go run examples/sec-win-server.go \
    --server-addr <server_address> \
    --secure-server-port <port> \
    --cert-subject <certificate_subject> \
    --ldap-address <ldap_server_address> \
    --ldap-users-dn <ldap_users_dn> \
    --ldap-service-account-spn <ldap_service_account_spn>
```

### Flags

- `server-addr`: The address the server will listen on.
- `secure-server-port`: The port the secure server will listen on.
- `cert-subject`: The subject of the certificate to use.
- `ldap-address`: The address of the LDAP server.
- `ldap-users-dn`: The DN for users in the LDAP server.
- `ldap-service-account-spn`: The SPN for the service account in the LDAP server.
- `from-current-user`: Whether to retrieve the certificate from the `CurrentUser` store instead of the `LocalMachine` store.

## Integration Testing

The `integration_tests` package contains tests for both NTLM and Kerberos authentication.

### Running NTLM Tests

NTLM tests can be run locally by spawning the test server and the test runner on the same machine.

1.  Build the test server:
    ```powershell
    go build -o testserver.exe ./integration_tests/cmd/testserver/main.go
    ```
2.  Run the test server:
    ```powershell
    .\testserver.exe --addr 127.0.0.1:8080 --use-ntlm=true
    ```
3.  Run the tests:
    ```powershell
    go test -v ./integration_tests -server-url http://127.0.0.1:8080 -auth-mode ntlm
    ```

### Running Kerberos Tests

Kerberos tests require the test server and the test runner to be on **separate machines** within the same Active Directory domain. This is because Windows handles local Kerberos authentication (Loopback) differently than remote authentication.

1.  Deploy and run `testserver.exe` on Machine A (the "server").
2.  Run the tests from Machine B (the "client") pointing to Machine A:
    ```powershell
    go test -v ./integration_tests -server-url http://<machine-a-hostname>:8080 -auth-mode kerberos
    ```

## Code Coverage

`gwim` supports code coverage collection for out-of-process integration tests using Go 1.22's `-cover` instrumentation.

1.  Build an instrumented test server:
    ```powershell
    go build -cover -o testserver.exe ./integration_tests/cmd/testserver/main.go
    ```
2.  Run the server with `GOCOVERDIR` set to an output directory:
    ```powershell
    mkdir coverage_data
    $env:GOCOVERDIR="coverage_data"
    .\testserver.exe --addr 127.0.0.1:8080 --use-ntlm=true
    ```
3.  Run your integration tests as usual.
4.  Stop the server (Ctrl+C). The server will gracefully shut down and flush coverage data to the `coverage_data` directory.
5.  View the coverage percentage:
    ```powershell
    go tool covdata percent -i=coverage_data
    ```
6.  Generate an HTML report:
    ```powershell
    go tool covdata textfmt -i=coverage_data -o coverage.out
    go tool cover '-html=coverage.out'
    ```

