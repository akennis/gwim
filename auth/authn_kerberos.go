package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

func KerberosAuthn(serverCreds *sspi.Credentials) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(AUTHORIZATION)
			if !strings.HasPrefix(authHeader, NEGOTIATE_SPC) {
				w.Header().Set(WWW_AUTH, NEGOTIATE)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			token64 := authHeader[TOKEN_OFFSET:]
			clientToken, err := base64.StdEncoding.DecodeString(token64)
			if err != nil {
				http.Error(w, "Invalid Token", http.StatusBadRequest)
				return
			}

			krbCtx, authDone, _, err := kerberos.NewServerContext(serverCreds, clientToken)
			if err != nil {
				http.Error(w, "Authentication Failed", http.StatusUnauthorized)
				return
			}
			if !authDone {
				http.Error(w, "Authentication Failed", http.StatusUnauthorized)
				return
			}

			username, err := krbCtx.GetUsername()
			if err != nil {
				http.Error(w, "Identity Error", http.StatusInternalServerError)
				return
			}
			username = strings.Split(username, "@")[0]
			username = strings.ToLower(username)

			usernameContext := context.WithValue(r.Context(), ContextKeyUsername, username)
			r = r.WithContext(usernameContext)
			next.ServeHTTP(w, r)
		})
	}
}
