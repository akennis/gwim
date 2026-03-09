# gwim

`gwim` / Go Windows Integrated Middleware is a Go library that simplifies HTTP server security through native Windows integration, including:
* authentication middleware via Windows SSPI: Kerberos or NTLM
* authorization middleware based on LDAP group lookup
* TLS certificate retrieval from the Windows certificate store

Using this library you can deploy a server application in an Active Directory environment that is secure *and also self-contained* (i.e. a single exe as opposed to a complex IIS / NGINX / Apache deployment).

> [!NOTE]
> Although authentication supports both Kerberos and NTLM, **Kerberos should be used in production** as it is significantly more secure. NTLM support is included only to facilitate local development where the developer is hitting the server from a browser on the same host (a scenario where only NTLM works).

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

## Prerequisites

| Requirement | Needed for |
|---|---|
| Windows OS | All features (library uses Windows SSPI / CryptoAPI) |
| Active Directory domain membership | Kerberos authentication |
| A registered SPN for the server host (e.g. `HTTP/myserver.corp.local`) | Kerberos authentication |
| A certificate imported into the Windows certificate store | `GetCertificate` |
| LDAP-reachable domain controller + a service account SPN | `NewLdapGroupProvider` |

## Installation

This package is only supported on Windows. Run inside your Go module (or simply import the package and run `go mod tidy`):

```bash
go get github.com/akennis/gwim
```

## Quick Start

The snippet below is the smallest possible secure server using `gwim`. It retrieves a TLS certificate from the Windows certificate store, wraps a handler with Kerberos authentication, and starts listening.

```go
package main

import (
    "crypto/tls"
    "log"
    "net/http"

    "github.com/akennis/gwim"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        username, _ := gwim.User(r)
        w.Write([]byte("Hello, " + username))
    })

    // Wrap the handler with Kerberos authentication (useNTLM = false)
    handler, err := gwim.NewSSPIHandler(mux, false)
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve a TLS certificate from the Windows certificate store
    cert, err := gwim.GetCertificate("myserver.corp.local", false)
    if err != nil {
        log.Fatal(err)
    }

    srv := &http.Server{
        Addr:    ":8443",
        Handler: handler,
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{cert},
        },
    }
    log.Fatal(srv.ListenAndServeTLS("", ""))
}
```

## How It Works

Requests flow through the middleware chain in the following order:

```
Client Request
  │
  ▼
SSPI Handler (Kerberos or NTLM negotiation)
  │  ── sets the authenticated username in the request context
  ▼
LDAP Group Provider (optional)
  │  ── looks up the user's group memberships and adds them to the context
  ▼
Your Application Handler
  │  ── reads username via gwim.User(r)
  │  ── reads groups  via gwim.UserGroups(r)
```

> [!IMPORTANT]
> **Middleware must be applied in reverse execution order.** Wrap your router with the LDAP provider first, then wrap the result with the SSPI handler. The LDAP provider depends on the username that the SSPI handler places in the context.

## API

The `gwim` package provides the following functions:

### Authentication

- `NewSSPIHandler(next http.Handler, useNTLM bool, options ...auth.AuthOptions) (http.Handler, error)` — Creates an authentication middleware that wraps an existing `http.Handler`. The `useNTLM` boolean selects NTLM or Kerberos. Optional `auth.AuthOptions` allow customizing error handlers. Returns an error if Windows SSPI credentials cannot be acquired (e.g. the `Negotiate` security package is unavailable).

- `ConfigureNTLM(server *http.Server)` — Configures the `http.Server` with the `ConnContext` callback required for NTLM connection tracking. NTLM is connection-oriented — each TCP connection carries its own authentication state. This function assigns a unique ID to every connection so the NTLM handler can track multi-step token exchanges across requests on the same connection. **This call is not needed for Kerberos.**

### LDAP Group Authorization

- `NewLdapGroupProvider(next http.Handler, ldapAddress, ldapUsersDN, ldapServiceAccountSPN string, options ...auth.AuthOptions) http.Handler` — Returns a middleware that enriches the request context with the authenticated user's LDAP group memberships.

  | Parameter | Example | Description |
  |---|---|---|
  | `ldapAddress` | `ldap://dc01.corp.local` | Address of the LDAP / domain controller |
  | `ldapUsersDN` | `OU=Users,DC=corp,DC=local` | Distinguished Name of the OU containing user accounts |
  | `ldapServiceAccountSPN` | `HTTP/myserver.corp.local` | SPN used for Kerberos authentication to the LDAP server |

### Request Context Helpers

- `User(r *http.Request) (string, bool)` — Returns the authenticated username from the request context.
- `SetUser(r *http.Request, username string) *http.Request` — Injects a username into the request context, allowing an application to manage sessions itself and bypass per-request authentication.
- `UserGroups(r *http.Request) ([]string, bool)` — Returns the user's group memberships from the request context.
- `SetUserGroups(r *http.Request, groups []string) *http.Request` — Injects group memberships into the request context, allowing an application to cache groups itself and bypass the LDAP provider.

Use `SetUser` and `SetUserGroups` to restore a previously authenticated identity from a session store, avoiding re-authentication and LDAP lookups on every request:
```go
// In your session middleware, before the SSPI handler runs:
if sessionUser, ok := getSession(r); ok {
    r = gwim.SetUser(r, sessionUser)
    r = gwim.SetUserGroups(r, sessionUser.Groups)
}
```
See [sec-win-server.go](examples/sec-win-server.go) for a full working example of this pattern.

### TLS Certificate

- `GetCertificate(certSubject string, fromCurrentUser bool) (tls.Certificate, error)` — Retrieves a TLS certificate from the Windows certificate store. When `fromCurrentUser` is `true`, the `CurrentUser` store is searched; otherwise `LocalMachine` is used.

### Exported Constants

- `ContextKeyConnID` — The context key used internally by `ConfigureNTLM` to track connection IDs. Exported so that advanced users can access the raw connection ID if needed.

### Error Handling (`auth.AuthOptions`)

Both `NewSSPIHandler` and `NewLdapGroupProvider` accept a variadic `auth.AuthOptions` struct to customize error responses. Each field is an `AuthErrorHandler func(w http.ResponseWriter, r *http.Request, err error)`:

| Field | Triggered when… |
|---|---|
| `OnUnauthorized` | The `Authorization` header is missing or invalid |
| `OnInvalidToken` | The base64 token from the client is malformed |
| `OnAuthFailed` | An error occurs during the SSPI/GSSAPI token exchange |
| `OnIdentityError` | The username cannot be retrieved after successful auth |
| `OnLdapConnectionError` | A connection to the LDAP server cannot be established |
| `OnLdapLookupError` | An error occurs during an LDAP search or lookup |
| `OnGeneralError` | Catch-all: fills in for any of the above handlers that is not explicitly set |

If no options are provided, sensible defaults are used (plain-text HTTP error responses).

## Usage Examples

See the [examples](examples) directory for examples of how to use `gwim`:
* [Minimal secure server via GWIM](examples/min-win-server.go)
* [Session-enabled secure server via gwim](examples/sec-win-server.go)
  * this example demonstrates how authentication and authorization results from the provided middleware can be used in conjunction with sessions and caching to produce an efficient and secure server.

## Integration Testing

The `integration_tests` package contains client / sever tests for both NTLM and Kerberos authentication.

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
