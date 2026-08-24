# gwim

**Windows-native Kerberos/NTLM authentication and TLS for Go HTTP servers.**

Deploying a Go service inside a corporate Active Directory domain normally means standing up IIS or a reverse proxy just to get Windows integrated authentication, authorization, and TLS. `gwim` removes that requirement. It wraps any `http.Handler` with Windows-native Kerberos authentication, enriches the request context with LDAP group memberships, and pulls TLS certificates straight from the Windows certificate store — letting you ship a single self-contained web server `.exe` that runs seamlessly in a Windows domain environment. With `gwim`, you can run Go websites securely right where your users are and just how your Windows infrastructure is configured.

## Prerequisites

| Requirement | Needed for |
|---|---|
| Windows OS | All features (library uses Windows SSPI / CryptoAPI) |
| Active Directory domain membership | Kerberos authentication |
| A registered SPN for the server host (e.g. `HTTP/myserver.corp.local`) | Kerberos authentication |
| A certificate imported into the Windows certificate store | `GetWin32Cert` / `GetCertificateFunc` |
| LDAP-reachable domain controller + a service account SPN | `NewLDAPProvider` |

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

    // Create a Kerberos authentication provider
    sspiProvider, _ := gwim.NewSSPIProvider()
    defer sspiProvider.Close()

    // Retrieve a TLS certificate from the Windows certificate store
    certSource, _ := gwim.GetWin32Cert("myserver.corp.local", gwim.CertStoreLocalMachine)
    defer certSource.Close()

    srv := &http.Server{
        Addr:    ":8443",
        Handler: sspiProvider.Middleware(mux),
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
SSPI Middleware (Kerberos or NTLM negotiation)
  │  ── sets the authenticated username in the request context
  ▼
LDAP Middleware (optional)
  │  ── looks up the user's group memberships and adds them to the context
  ▼
Your Application Handler
  │  ── reads username via gwim.User(r)
  │  ── reads groups  via gwim.UserGroups(r)
```

> [!IMPORTANT]
> **Middleware Order:** `SSPIProvider` must always be applied *before* `LDAPProvider` (i.e. `SSPIProvider` should be the outermost middleware). This ensures the user's identity is established in the request context before the LDAP provider attempts to look up their group memberships.

## Usage Examples

See the [examples](examples) directory for complete, runnable servers:

- [**Minimal secure server**](examples/min-win-server/main.go) — TLS + Kerberos/NTLM authentication with optional LDAP group lookup, in under 200 lines.
- [**Session-enabled secure server**](examples/sec-win-server/main.go) — adds session management and caching so that authentication and LDAP lookups happen once per session rather than on every request, with graceful shutdown and zero-downtime certificate rotation.

## API

### Authentication

`gwim` uses the **Middleware Factory Pattern**: create a provider once at startup, then register its `.Middleware` method with any router's `Use()` call or use it to wrap handlers manually. The `.Middleware` method satisfies the standard `func(http.Handler) http.Handler` signature, making it compatible with any router that supports standard Go middleware.

#### `NewSSPIProvider`

```go
sspiProvider, err := gwim.NewSSPIProvider(opts ...SSPIOption) (*SSPIProvider, error)
```

Acquires Windows SSPI credentials and returns a provider. Any credential acquisition error is surfaced here at startup rather than on the first request.

```go
// Kerberos (production default)
sspiProvider, err := gwim.NewSSPIProvider()

// NTLM (local / non-domain development)
sspiProvider, err := gwim.NewSSPIProvider(gwim.WithNTLM())

// With custom error handling
sspiProvider, err := gwim.NewSSPIProvider(
    gwim.WithNTLM(),
    gwim.WithSSPIErrorHandlers(gwim.AuthErrorHandlers{
        OnGeneralError: myErrorHandler,
    }),
)
```

Use the provider:

```go
// Standard net/http
handler := sspiProvider.Middleware(mux)

// Any router with Use()
router.Use(sspiProvider.Middleware)
```

**SSPIOption functions:**

| Option | Description |
|---|---|
| `WithNTLM()` | Use NTLM instead of Kerberos. Required for non-domain or localhost scenarios. |
| `WithSSPIErrorHandlers(h AuthErrorHandlers)` | Override default error responses. |

**Lifecycle:** Call `sspiProvider.Close()` on server shutdown to release Windows credential handles.

> [!NOTE]
> **Kerberos should be used in production** as it is significantly more secure. NTLM support is included only to facilitate local development where the developer is hitting the server from a browser on the same host (a scenario where Kerberos loopback authentication does not work).

#### `ConfigureNTLM`

```go
gwim.ConfigureNTLM(server *http.Server)
```

Configures the `http.Server` with the `ConnContext` callback required for NTLM connection tracking. NTLM is connection-oriented — each TCP connection carries its own authentication state. This function assigns a unique ID to every connection so the NTLM handler can correlate the two-step token exchange across requests on the same keep-alive connection. **Only required when using NTLM; not needed for Kerberos.**

### LDAP Group Authorization

#### `NewLDAPProvider`

```go
ldapProvider, err := gwim.NewLDAPProvider(opts ...LDAPOption) (*LDAPProvider, error)
```

Returns a provider that enriches an authenticated request's context with the user's Active Directory group memberships (transitively, via the `tokenGroups` attribute). Groups are returned as LDAP Distinguished Names (DNs), e.g. `CN=AppAdmins,OU=Groups,DC=corp,DC=local`.

**Startup validation:** `NewLDAPProvider` performs a synchronous connectivity check before returning. It opens a TLS (LDAPS) connection to the configured address, authenticates via GSSAPI/Kerberos bind using the server's current-user credentials, and executes a RootDSE search. If any step fails, an error is returned here at startup rather than on the first request.

At runtime, the provider maintains an internal connection pool (capacity: 10). A pooled connection older than its TTL is discarded before use. A lookup that fails on a pooled connection is assumed to have hit a stale one, so the connection is closed and the lookup is retried exactly once on a freshly dialled connection; a second failure is reported to the caller.

```go
ldapProvider, err := gwim.NewLDAPProvider(
    gwim.WithLDAPAddress("dc01.corp.local:636"),
    gwim.WithLDAPUsersDN("OU=Users,DC=corp,DC=local"),
    gwim.WithLDAPServiceAccountSPN("LDAP/DC1.corp.local"),
)
if err != nil {
    log.Fatalf("failed to create LDAP provider: %v", err)
}

// Wrap the LDAP-wrapped handler with SSPI (SSPI runs first)
handler = sspiProvider.Middleware(ldapProvider.Middleware(mux))

// Or with a router
router.Use(sspiProvider.Middleware)
router.Use(ldapProvider.Middleware)
```

**LDAPOption functions:**

| Option | Description |
|---|---|
| `WithLDAPAddress(addr string)` | Host and port of the LDAP / domain controller (LDAPS is always used) |
| `WithLDAPUsersDN(dn string)` | Distinguished Name of the OU containing user accounts |
| `WithLDAPServiceAccountSPN(spn string)` | SPN of the LDAP service account used for GSSAPI bind |
| `WithLDAPTimeout(d time.Duration)` | Per-operation timeout; defaults to `DefaultLdapTimeout` (5s) |
| `WithLDAPConnectionTTL(d time.Duration)` | Max lifetime of a pooled connection; defaults to `DefaultLdapTTL` (1h) |
| `WithLDAPErrorHandlers(h AuthErrorHandlers)` | Override default error responses |

**Lifecycle:** Call `ldapProvider.Close()` on server shutdown to drain the connection pool and release Windows credentials used for the LDAP bind.

#### `Groups`

```go
func (p *LDAPProvider) Groups(ctx context.Context, username string) ([]string, error)
```

The lookup `Middleware` performs, made available to callers that have no request in hand — re-checking membership on a timer for a username recovered from a token, for example. It uses the same pooled connections and service-account bind, and returns the same transitive group DNs.

```go
groups, err := ldapProvider.Groups(ctx, "ajones")
switch {
case err == nil:
    // groups holds the user's transitive memberships as DNs.
case errors.Is(err, gwim.ErrUserNotFound):
    // The directory answered: no such account, disabled, or ambiguous.
    // A definitive deny — not an outage.
case errors.Is(err, gwim.ErrLDAPConnection), errors.Is(err, gwim.ErrLDAPLookup):
    // Membership is unknown. Decide whether to fail open or closed.
default:
    // ctx.Err(): the caller's deadline elapsed or the call was cancelled.
}
```

**Errors.** Every directory failure wraps one of three sentinels, so callers can classify without parsing messages. The concrete error from the directory is wrapped alongside and stays reachable through `errors.Unwrap`.

| Sentinel | Meaning | Membership |
|---|---|---|
| `ErrLDAPConnection` | The directory could not be reached, or the GSSAPI bind failed | Unknown |
| `ErrLDAPLookup` | The directory was reachable but the search failed | Unknown |
| `ErrUserNotFound` | The directory answered; the account does not exist, is disabled, or matched more than one entry. Wraps `ErrLDAPLookup` | Definitively none |

The `ErrUserNotFound` / `ErrLDAPLookup` split is the one that matters for an authorization decision: the first is an answer, the second is an outage. Code that only needs "could not determine membership" can test `ErrLDAPLookup` alone and still catch both.

**Context.** `ctx` bounds how long `Groups` waits, not the search itself. The underlying `go-ldap` client applies its timeout per connection rather than per call, so an in-flight search cannot be interrupted. When `ctx` is done first, `Groups` returns `ctx.Err()` promptly and the search runs to completion in the background, bounded by `WithLDAPTimeout`, after which its connection returns to the pool. The effective wait is `min(ctx deadline, WithLDAPTimeout)`.

`Middleware` and `Groups` share one pool and one `Close`; using both on the same provider is expected.

### Outbound Authentication (Client)

Authenticate requests *to* another service as the calling process's own Windows identity — for a service, the account it runs under. No keytab, no stored password, and no user impersonation.

- `NewNegotiateTransport(spn string, opts ...ClientTransportOption) (http.RoundTripper, io.Closer, error)` — Kerberos (SPNEGO) against `spn`, e.g. `HTTP/api.example.local`. Handles multi-leg negotiation and verifies the server's mutual authentication token when one is returned. Pass `WithNTLMFallback` to also attempt NTLM-within-SPNEGO when the server rejects Kerberos with a bare 401, matching browser behaviour.

Credentials are acquired up front so a misconfigured account fails at startup rather than on the first request; call `Close()` on the returned `io.Closer` on shutdown.

| Option | Description |
| --- | --- |
| `WithClientBaseTransport(rt http.RoundTripper)` | RoundTripper that sends the authenticated requests |
| `WithNTLMFallback()` | Fall back to NTLM-within-SPNEGO when the server rejects Kerberos with a bare 401; also switches the default base transport to one that pins connections and disables HTTP/2 |

```go
rt, closer, err := gwim.NewNegotiateTransport("HTTP/api.example.local")
if err != nil {
    log.Fatalf("failed to prepare Negotiate transport: %v", err)
}
defer closer.Close()

client := &http.Client{Transport: rt, Timeout: 15 * time.Second}
resp, err := client.Get("https://api.example.local/auth/token")
```

Build requests that carry a body with `http.NewRequest` and a `*bytes.Reader`, `*bytes.Buffer` or `*strings.Reader` so the body can be replayed if the server needs more than one leg. A `401` the server does not accompany with a continuation token is returned to the caller unchanged.

**NTLM and connections:** NTLM is connection-oriented — the server binds a half-finished handshake to the connection its challenge arrived on. When `WithNTLMFallback` is set, the default base transport is replaced with one that allows a single connection per host with HTTP/2 disabled, and requests are serialised so two handshakes cannot interleave on that connection. Expect one request at a time to the target. If you supply your own base transport with `WithClientBaseTransport`, it must preserve those properties.

### Request Context Helpers

- `User(r *http.Request) (string, bool)` — Returns the authenticated username from the request context.
- `SetUser(r *http.Request, username string) *http.Request` — Injects a username into the request context. If a username is already present when the SSPI middleware runs, authentication is skipped — use this to restore a session without re-running SSPI.
- `UserGroups(r *http.Request) ([]string, bool)` — Returns the user's group memberships from the request context as LDAP Distinguished Names (DNs), e.g. `CN=AppAdmins,OU=Groups,DC=corp,DC=local`.
- `SetUserGroups(r *http.Request, groups []string) *http.Request` — Injects group memberships into the request context. If groups are already present when the LDAP middleware runs, the LDAP lookup is skipped — use this to restore cached groups from a session.

Use `SetUser` and `SetUserGroups` together to restore a previously authenticated identity from a session store, avoiding re-authentication and LDAP lookups on every request:

```go
// In your session middleware, before the SSPI middleware runs:
if sessionUser, ok := getSession(r); ok {
    r = gwim.SetUser(r, sessionUser)
    r = gwim.SetUserGroups(r, sessionUser.Groups)
}
```

See [sec-win-server/main.go](examples/sec-win-server/main.go) for a full working example of this pattern.

### TLS Certificate

- `GetWin32Cert(certSubject string, store CertStore) (*CertificateSource, error)` — Retrieves a TLS certificate from the Windows certificate store by Common Name. Use `CertStoreLocalMachine` or `CertStoreCurrentUser` for `store`. The certificate is validated before being returned: it must not be expired, must carry `ExtKeyUsageServerAuth`, and its full issuer chain must pass verification via the Windows CryptoAPI. The returned `CertificateSource.Certificate` is a `tls.Certificate` ready for use in `tls.Config.Certificates`. Call `Close()` on the source when it is no longer needed (e.g. on server shutdown) to release Windows store handles.

- `GetCertificateFunc(certSubject string, store CertStore, refreshThreshold, retryInterval time.Duration) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), io.Closer, error)` — Like `GetWin32Cert` but returns a `tls.Config.GetCertificate` callback that transparently refreshes the certificate in the background when it is within `refreshThreshold` of expiry, enabling zero-downtime rotation. Pass `DefaultRefreshThreshold` and `DefaultRetryInterval` for standard values. Call `Close()` on the returned `io.Closer` after `http.Server.Shutdown` returns.

### Error Handling (`AuthErrorHandlers`)

Both `WithSSPIErrorHandlers` and `WithLDAPErrorHandlers` accept an `AuthErrorHandlers` struct to customize error responses. Each field is an `AuthErrorHandler func(w http.ResponseWriter, r *http.Request, err error)`:

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

Requests do not progress to the next request hander in the chain once an error has occurred.  The error handler is executed and control is sent back up the request hander chain (i.e. the earlier handlers).

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
