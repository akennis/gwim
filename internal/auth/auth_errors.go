// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import "net/http"

// AuthErrorHandler is a function that handles an authentication error.
type AuthErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// AuthErrorHandlers allows customizing the behavior of the authentication handlers.
type AuthErrorHandlers struct {
	// OnUnauthorized is called when the authentication header is missing or invalid.
	OnUnauthorized AuthErrorHandler
	// OnInvalidToken is called when the base64 token provided by the client is malformed.
	OnInvalidToken AuthErrorHandler
	// OnAuthFailed is called when an error occurs during the SSPI/GSAPI token exchange.
	OnAuthFailed AuthErrorHandler
	// OnIdentityError is called when the username cannot be retrieved after successful authentication.
	OnIdentityError AuthErrorHandler
	// OnGeneralError is a catch-all handler for any error if the specific handler is not set.
	OnGeneralError AuthErrorHandler
	// OnLdapConnectionError is called when a connection to the LDAP server cannot be established.
	OnLdapConnectionError AuthErrorHandler
	// OnLdapLookupError is called when an error occurs during an LDAP search or lookup.
	OnLdapLookupError AuthErrorHandler
}

// DefaultAuthErrorHandlers returns the default authentication options with hardcoded behaviors.
func DefaultAuthErrorHandlers() AuthErrorHandlers {
	return AuthErrorHandlers{
		OnUnauthorized: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		},
		OnInvalidToken: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Invalid Token", http.StatusBadRequest)
		},
		OnAuthFailed: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Authentication Failed", http.StatusUnauthorized)
		},
		OnIdentityError: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Identity Error", http.StatusInternalServerError)
		},
		OnLdapConnectionError: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "LDAP connection problem, defaulting to not authorized", http.StatusInternalServerError)
		},
		OnLdapLookupError: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "LDAP group lookup problem, defaulting to not authorized", http.StatusInternalServerError)
		},
	}
}

// ApplyGeneralError applies the OnGeneralError handler to any unset specific handlers.
func (o *AuthErrorHandlers) ApplyGeneralError() {
	if o.OnGeneralError == nil {
		return
	}
	if o.OnUnauthorized == nil {
		o.OnUnauthorized = o.OnGeneralError
	}
	if o.OnInvalidToken == nil {
		o.OnInvalidToken = o.OnGeneralError
	}
	if o.OnAuthFailed == nil {
		o.OnAuthFailed = o.OnGeneralError
	}
	if o.OnIdentityError == nil {
		o.OnIdentityError = o.OnGeneralError
	}
	if o.OnLdapConnectionError == nil {
		o.OnLdapConnectionError = o.OnGeneralError
	}
	if o.OnLdapLookupError == nil {
		o.OnLdapLookupError = o.OnGeneralError
	}
}

var defaultHandlers = DefaultAuthErrorHandlers()

// GetOnUnauthorized returns the OnUnauthorized handler or the default.
func (o AuthErrorHandlers) GetOnUnauthorized() AuthErrorHandler {
	if o.OnUnauthorized != nil {
		return o.OnUnauthorized
	}
	return defaultHandlers.OnUnauthorized
}

// GetOnInvalidToken returns the OnInvalidToken handler or the default.
func (o AuthErrorHandlers) GetOnInvalidToken() AuthErrorHandler {
	if o.OnInvalidToken != nil {
		return o.OnInvalidToken
	}
	return defaultHandlers.OnInvalidToken
}

// GetOnAuthFailed returns the OnAuthFailed handler or the default.
func (o AuthErrorHandlers) GetOnAuthFailed() AuthErrorHandler {
	if o.OnAuthFailed != nil {
		return o.OnAuthFailed
	}
	return defaultHandlers.OnAuthFailed
}

// GetOnIdentityError returns the OnIdentityError handler or the default.
func (o AuthErrorHandlers) GetOnIdentityError() AuthErrorHandler {
	if o.OnIdentityError != nil {
		return o.OnIdentityError
	}
	return defaultHandlers.OnIdentityError
}

// GetOnLdapConnectionError returns the OnLdapConnectionError handler or the default.
func (o AuthErrorHandlers) GetOnLdapConnectionError() AuthErrorHandler {
	if o.OnLdapConnectionError != nil {
		return o.OnLdapConnectionError
	}
	return defaultHandlers.OnLdapConnectionError
}

// GetOnLdapLookupError returns the OnLdapLookupError handler or the default.
func (o AuthErrorHandlers) GetOnLdapLookupError() AuthErrorHandler {
	if o.OnLdapLookupError != nil {
		return o.OnLdapLookupError
	}
	return defaultHandlers.OnLdapLookupError
}
