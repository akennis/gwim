# gwim

**Windows-native Kerberos/NTLM authentication and TLS for Go HTTP servers.**

Deploying a Go service inside a corporate Active Directory domain normally means standing up IIS or a reverse proxy just to get Windows Integrated Authentication. `gwim` removes that requirement. It wraps any `http.Handler` with Kerberos authentication, enriches the request context with LDAP group memberships, and pulls TLS certificates straight from the Windows certificate store — letting you ship a single self-contained `.exe`.

## Prerequisites

| Requirement | Needed for |
|---|---|
| Windows OS | All features (library uses Windows SSPI / CryptoAPI) |
| Active Directory domain membership | Kerberos authentication |
| A registered SPN for the server host (e.g. `HTTP/myserver.corp.local`) | Kerberos authentication |
| A certificate imported into the Windows certificate store | `GetWin32Cert` / `GetCertificateFunc` |
| LDAP-reachable domain controller + a service account SPN | `NewLdapGroupProvider` |

## Installation

```bash
go get github.com/akennis/gwim
```

## Quick Start

The snippet below is the smallest possible secure server using `gwim`. It retrieves a TLS certificate from the Windows certificate store, wraps a handler with Kerberos authentication, and starts listening. Error handling is omitted for brevity.

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
    handler, _ := gwim.NewSSPIHandler(mux, false)

    // Retrieve a TLS certificate from the Windows certificate store
    certSource, _ := gwim.GetWin32Cert("myserver.corp.local", gwim.CertStoreLocalMachine)
    defer certSource.Close()

    srv := &http.Server{
        Addr:    ":8443",
        Handler: handler,
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{certSource.Certificate},
        },
    }

    // Windows authenticates the current domain user transparently —
    // no login prompt, no credentials to manage.
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

## Usage Examples

See the [examples](examples) directory for complete, runnable servers:

- [**Minimal secure server**](examples/min-win-server/main.go) — TLS + Kerberos/NTLM authentication with optional LDAP group lookup, in under 200 lines.
- [**Session-enabled secure server**](examples/sec-win-server/main.go) — adds session management and caching so that authentication and LDAP lookups happen once per session rather than on every request, with graceful shutdown and zero-downtime certificate rotation.

## API

### Authentication

- `NewSSPIHandler(next http.Handler, useNTLM bool, options ...AuthErrorHandlers) (http.Handler, error)` — Creates a Windows native authentication middleware that wraps an existing `http.Handler`. The `useNTLM` boolean selects NTLM or Kerberos. Optional `AuthErrorHandlers` allow customizing error responses. Returns an error if Windows SSPI credentials cannot be acquired (e.g. the `Negotiate` security package is unavailable). On success, the authenticated username is stored in the request context and readable via `gwim.User(r)`. On failure, the appropriate error handler is invoked (default: 401 Unauthorized).

> [!NOTE]
> **Kerberos should be used in production** as it is significantly more secure. NTLM support is included only to facilitate local development where the developer is hitting the server from a browser on the same host (a scenario where Kerberos loopback authentication does not work).

- `ConfigureNTLM(server *http.Server)` — Configures the `http.Server` with the `ConnContext` callback required for NTLM connection tracking. NTLM is connection-oriented — each TCP connection carries its own authentication state. This function assigns a unique ID to every connection so the NTLM handler can correlate the two-step token exchange across requests on the same keep-alive connection. **Only required when using NTLM; not needed for Kerberos.**

### LDAP Group Authorization

- `NewLdapGroupProvider(next http.Handler, ldapAddress, ldapUsersDN, ldapServiceAccountSPN string, ldapTimeout, ldapTTL time.Duration, options ...AuthErrorHandlers) http.Handler` — Returns a middleware that enriches the request context with the authenticated user's LDAP group memberships (transitively).

  | Parameter | Example | Description |
  |---|---|---|
  | `ldapAddress` | `dc01.corp.local:636` | Host and port of the LDAP / domain controller (LDAPS is always used) |
  | `ldapUsersDN` | `OU=Users,DC=corp,DC=local` | Distinguished Name of the OU containing user accounts |
  | `ldapServiceAccountSPN` | `HTTP/myserver.corp.local` | SPN of the LDAP server |
  | `ldapTimeout` | `gwim.DefaultLdapTimeout` | Per-operation timeout for every LDAP call; pass `gwim.DefaultLdapTimeout` for the standard 5-second value |
  | `ldapTTL` | `gwim.DefaultLdapTTL` | Maximum lifetime of a connection to prevent stale Kerberos tickets; pass `gwim.DefaultLdapTTL` for 1 hour |

### Request Context Helpers

- `User(r *http.Request) (string, bool)` — Returns the authenticated username from the request context.
- `SetUser(r *http.Request, username string) *http.Request` — Injects a username into the request context. If a username is already present when the SSPI handler runs, authentication is skipped — use this to restore a session without re-running SSPI.
- `UserGroups(r *http.Request) ([]string, bool)` — Returns the user's group memberships from the request context.
- `SetUserGroups(r *http.Request, groups []string) *http.Request` — Injects group memberships into the request context. If groups are already present when the LDAP provider runs, the LDAP lookup is skipped — use this to restore cached groups from a session.

Use `SetUser` and `SetUserGroups` together to restore a previously authenticated identity from a session store, avoiding re-authentication and LDAP lookups on every request:

```go
// In your session middleware, before the SSPI handler runs:
if sessionUser, ok := getSession(r); ok {
    r = gwim.SetUser(r, sessionUser)
    r = gwim.SetUserGroups(r, sessionUser.Groups)
}
```

See [sec-win-server/main.go](examples/sec-win-server/main.go) for a full working example of this pattern.

### TLS Certificate

- `GetWin32Cert(certSubject string, store CertStore) (*CertificateSource, error)` — Retrieves a TLS certificate from the Windows certificate store by Common Name. Use `CertStoreLocalMachine` or `CertStoreCurrentUser` for `store`. The returned `CertificateSource.Certificate` is a `tls.Certificate` ready for use in `tls.Config.Certificates`. Call `Close()` on the source when it is no longer needed (e.g. on server shutdown) to release Windows store handles.

- `GetCertificateFunc(certSubject string, store CertStore, refreshThreshold, retryInterval time.Duration) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error)` — Like `GetWin32Cert` but returns a `tls.Config.GetCertificate` callback that transparently refreshes the certificate in the background when it is within `refreshThreshold` of expiry, enabling zero-downtime rotation. Pass `DefaultRefreshThreshold` and `DefaultRetryInterval` for standard values. Call `Close()` on the returned `io.Closer` after `http.Server.Shutdown` returns.

### Error Handling (`AuthErrorHandlers`)

Both `NewSSPIHandler` and `NewLdapGroupProvider` accept a variadic `AuthErrorHandlers` struct to customize error responses. Each field is an `AuthErrorHandler func(w http.ResponseWriter, r *http.Request, err error)`:

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

## Integration Testing

The `integration_tests` package contains client/server tests for both NTLM and Kerberos authentication.

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
    go test -tags=integration -v ./integration_tests -server-url http://127.0.0.1:8080 -auth-mode ntlm
    ```

### Running Kerberos Tests

Kerberos tests require the test server and the test runner to be on **separate machines** within the same Active Directory domain. This is because Windows handles local Kerberos authentication (loopback) differently than remote authentication.

1.  Deploy and run `testserver.exe` on Machine A (the "server").
2.  Run the tests from Machine B (the "client") pointing to Machine A:
    ```powershell
    go test -tags=integration -v ./integration_tests -server-url http://<machine-a-hostname>:8080 -auth-mode kerberos
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

## License

This project is licensed under the BSD 3-Clause License — see the [LICENSE](LICENSE) file for details.
