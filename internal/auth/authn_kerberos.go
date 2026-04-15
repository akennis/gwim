// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

type kerberosServerContext interface {
	GetUsername() (string, error)
}

type kerberosProvider interface {
	NewServerContext(creds *sspi.Credentials, clientToken []byte) (kerberosServerContext, bool, []byte, error)
}

type defaultKerberosProvider struct{}

func (p *defaultKerberosProvider) NewServerContext(creds *sspi.Credentials, clientToken []byte) (kerberosServerContext, bool, []byte, error) {
	return kerberos.NewServerContext(creds, clientToken)
}

func KerberosAuthn(serverCreds *sspi.Credentials, opts AuthErrorHandlers) func(http.Handler) http.Handler {
	opts.ApplyGeneralError()
	return kerberosAuthn(serverCreds, &defaultKerberosProvider{}, opts)
}

func kerberosAuthn(serverCreds *sspi.Credentials, kp kerberosProvider, errHndlrs AuthErrorHandlers) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If a non-empty username is already in the context, skip authentication.
			if username, ok := r.Context().Value(ContextKeyUsername).(string); ok && username != "" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get(authorization)
			if !strings.HasPrefix(authHeader, negotiateSpc) {
				w.Header().Set(wwwAuthenticate, negotiate)
				errHndlrs.GetOnUnauthorized()(w, r, fmt.Errorf("requesting client to negotiate kerberos authentication"))
				return
			}

			token64 := authHeader[tokenOffset:]
			clientToken, err := base64.StdEncoding.DecodeString(token64)
			if err != nil {
				errHndlrs.GetOnInvalidToken()(w, r, err)
				return
			}

			krbCtx, authDone, _, err := kp.NewServerContext(serverCreds, clientToken)
			if err != nil {
				errHndlrs.GetOnAuthFailed()(w, r, err)
				return
			}
			if !authDone {
				errHndlrs.GetOnAuthFailed()(w, r, fmt.Errorf("negotiation in progress"))
				return
			}

			username, err := krbCtx.GetUsername()
			if err != nil {
				errHndlrs.GetOnIdentityError()(w, r, err)
				return
			}
			username = NormalizeUsername(username)

			usernameContext := context.WithValue(r.Context(), ContextKeyUsername, username)
			r = r.WithContext(usernameContext)
			next.ServeHTTP(w, r)
		})
	}
}
