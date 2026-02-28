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
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/patrickmn/go-cache"
)

const (
	NTLM     = "NTLM"
	NTLM_SPC = NTLM + " "
)

type SecPkgContext_Names struct {
	UserName *uint16
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

func NtlmAuthn(serverCreds *sspi.Credentials) func(http.Handler) http.Handler {
	authCache := cache.New(1*time.Minute, 2*time.Minute)
	authCache.OnEvicted(func(k string, v interface{}) {
		if s, ok := v.(*sspi.Context); ok {
			s.Release()
		}
	})

	handleNTLM := func(clientToken []byte, connID uint64) (string, []byte, bool, error) {
		var negoCtx *sspi.Context
		var isNewContext bool
		var authID string

		if connID != 0 {
			authID = fmt.Sprintf("N%d", connID)
			if cached, found := authCache.Get(authID); found {
				if s, ok := cached.(*sspi.Context); ok {
					negoCtx = s
				}
			}
		}

		if negoCtx == nil {
			isNewContext = true
			// For NTLM, we need connection-based tracking. REPLAY_DETECT is also good practice.
			negoCtx = sspi.NewServerContext(serverCreds, sspi.ASC_REQ_CONNECTION|sspi.ASC_REQ_REPLAY_DETECT)
		}

		outputToken := make([]byte, negotiate.PackageInfo.MaxToken)
		outBuf := sspi.SecBuffer{BufferType: sspi.SECBUFFER_TOKEN, Buffer: &outputToken[0], BufferSize: uint32(len(outputToken))}
		inBuf := sspi.SecBuffer{BufferType: sspi.SECBUFFER_TOKEN, Buffer: &clientToken[0], BufferSize: uint32(len(clientToken))}
		outDesc := sspi.NewSecBufferDesc([]sspi.SecBuffer{outBuf})
		inDesc := sspi.NewSecBufferDesc([]sspi.SecBuffer{inBuf})

		ret := negoCtx.Update(nil, outDesc, inDesc)
		if ret != sspi.SEC_E_OK && ret != sspi.SEC_I_CONTINUE_NEEDED {
			if isNewContext {
				negoCtx.Release() // Release if newly created context failed to update
			}
			return "", nil, false, ret
		}

		authDone := (ret == sspi.SEC_E_OK)
		n := outDesc.Buffers.BufferSize
		outputTokenBytes := outputToken[:n]

		if authDone {
			username, err := getSSPIUsername(negoCtx.Handle)
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
			authHeader := r.Header.Get(AUTHORIZATION)
			var token64 string
			if strings.HasPrefix(authHeader, NTLM_SPC) {
				token64 = authHeader[len(NTLM_SPC):]
			}

			if token64 == "" {
				w.Header().Add(WWW_AUTH, NTLM)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			clientToken, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token64))
			if err != nil {
				http.Error(w, "Invalid Token", http.StatusBadRequest)
				return
			}

			connID, _ := r.Context().Value(ContextKeyConnID).(uint64)
			authID := fmt.Sprintf("N%d", connID)

			username, outputToken, authDone, err := handleNTLM(clientToken, connID)

			if err != nil {
				if authID != "" {
					authCache.Delete(authID)
				}
				http.Error(w, "Authentication Failed", http.StatusUnauthorized)
				return
			}

			if !authDone {
				w.Header().Set(WWW_AUTH, NTLM+" "+base64.StdEncoding.EncodeToString(outputToken))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
