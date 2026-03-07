package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/ntlm"
	"github.com/patrickmn/go-cache"
)

const (
	NTLM     = "NTLM"
	NTLM_SPC = NTLM + " "
)

type SecPkgContext_Names struct {
	UserName *uint16
}

type ntlmServerContext interface {
	Update(outDesc, inDesc *sspi.SecBufferDesc) error
	Release() error
	GetUsername() (string, error)
}

type ntlmProvider interface {
	NewServerContext(creds *sspi.Credentials) ntlmServerContext
}

type defaultNtlmProvider struct{}

func (p *defaultNtlmProvider) NewServerContext(creds *sspi.Credentials) ntlmServerContext {
	return &sspiNtlmContext{sspi.NewServerContext(creds, sspi.ASC_REQ_CONNECTION|sspi.ASC_REQ_REPLAY_DETECT)}
}

type sspiNtlmContext struct {
	*sspi.Context
}

func (c *sspiNtlmContext) Update(outDesc, inDesc *sspi.SecBufferDesc) error {
	return c.Context.Update(nil, outDesc, inDesc)
}

func (c *sspiNtlmContext) Release() error {
	return c.Context.Release()
}

func (c *sspiNtlmContext) GetUsername() (string, error) {
	return getSSPIUsername(c.Context.Handle)
}

func getSSPIUsername(sctxt *sspi.CtxtHandle) (string, error) {
	var n SecPkgContext_Names
	ret := sspi.QueryContextAttributes(sctxt, 1, (*byte)(unsafe.Pointer(&n)))
	if ret != sspi.SEC_E_OK {
		return "", ret
	}
	defer sspi.FreeContextBuffer((*byte)(unsafe.Pointer(n.UserName)))
	return syscall.UTF16ToString((*[2 << 20]uint16)(unsafe.Pointer(n.UserName))[:]), nil
}

func NtlmAuthn(serverCreds *sspi.Credentials, options ...AuthOptions) func(http.Handler) http.Handler {
	authCache := cache.New(1*time.Minute, 2*time.Minute)
	var opts AuthOptions
	if len(options) > 0 {
		opts = options[0]
	}
	opts.ApplyGeneralError()
	return ntlmAuthn(serverCreds, &defaultNtlmProvider{}, authCache, opts)
}

func ntlmAuthn(serverCreds *sspi.Credentials, np ntlmProvider, authCache *cache.Cache, opts AuthOptions) func(http.Handler) http.Handler {
	authCache.OnEvicted(func(k string, v interface{}) {
		if s, ok := v.(ntlmServerContext); ok {
			s.Release()
		}
	})

	handleNTLM := func(clientToken []byte, connID uint64) (string, []byte, bool, error) {
		var negoCtx ntlmServerContext
		var isNewContext bool
		var authID string

		if connID != 0 {
			authID = fmt.Sprintf("N%d", connID)
			if cached, found := authCache.Get(authID); found {
				if s, ok := cached.(ntlmServerContext); ok {
					negoCtx = s
				}
			}
		}

		if negoCtx == nil {
			isNewContext = true
			negoCtx = np.NewServerContext(serverCreds)
		}

		outputToken := make([]byte, ntlm.PackageInfo.MaxToken)
		outBuf := sspi.SecBuffer{BufferType: sspi.SECBUFFER_TOKEN, Buffer: &outputToken[0], BufferSize: uint32(len(outputToken))}
		inBuf := sspi.SecBuffer{BufferType: sspi.SECBUFFER_TOKEN, Buffer: &clientToken[0], BufferSize: uint32(len(clientToken))}
		outDesc := sspi.NewSecBufferDesc([]sspi.SecBuffer{outBuf})
		inDesc := sspi.NewSecBufferDesc([]sspi.SecBuffer{inBuf})

		err := negoCtx.Update(outDesc, inDesc)
		if err != sspi.SEC_E_OK && err != sspi.SEC_I_CONTINUE_NEEDED {
			if isNewContext {
				negoCtx.Release() // Release if newly created context failed to update
			}
			return "", nil, false, err
		}

		authDone := (err == sspi.SEC_E_OK)
		n := outDesc.Buffers.BufferSize
		outputTokenBytes := outputToken[:n]

		if authDone {
			username, err := negoCtx.GetUsername()
			if err != nil {
				negoCtx.Release() // Done with context, release it.
				return "", nil, true, err
			}
			negoCtx.Release()
			return username, nil, true, nil
		}

		if authID == "" {
			if isNewContext {
				negoCtx.Release() // Could not generate an ID to track the context.
			}
			return "", nil, false, fmt.Errorf("missing connection ID for NTLM auth")
		}
		authCache.Set(authID, negoCtx, cache.DefaultExpiration)
		return "", outputTokenBytes, false, nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If the username is already in the context, skip authentication
			if _, ok := r.Context().Value(ContextKeyUsername).(string); ok {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get(AUTHORIZATION)
			var token64 string
			if strings.HasPrefix(authHeader, NTLM_SPC) {
				token64 = authHeader[len(NTLM_SPC):]
			}

			if token64 == "" {
				w.Header().Add(WWW_AUTH, NTLM)
				opts.GetOnUnauthorized()(w, r, fmt.Errorf("missing authentication header"))
				return
			}

			clientToken, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token64))
			if err != nil {
				opts.GetOnInvalidToken()(w, r, err)
				return
			}

			connID, _ := r.Context().Value(ContextKeyConnID).(uint64)
			authID := fmt.Sprintf("N%d", connID)

			username, outputToken, authDone, err := handleNTLM(clientToken, connID)

			if err != nil {
				if authID != "" {
					authCache.Delete(authID)
				}
				opts.GetOnAuthFailed()(w, r, err)
				return
			}

			if !authDone {
				w.Header().Set(WWW_AUTH, NTLM+" "+base64.StdEncoding.EncodeToString(outputToken))
				opts.GetOnUnauthorized()(w, r, fmt.Errorf("negotiation in progress"))
				return
			}

			// Auth is complete, remove from cache.
			if authID != "" {
				authCache.Delete(authID)
			}

			if strings.Contains(username, "@") {
				username = strings.Split(username, "@")[0]
			} else if strings.Contains(username, "\\") {
				parts := strings.Split(username, "\\")
				username = parts[len(parts)-1]
			}
			username = strings.ToLower(username)

			usernameContext := context.WithValue(r.Context(), ContextKeyUsername, username)
			r = r.WithContext(usernameContext)
			next.ServeHTTP(w, r)
		})
	}
}
