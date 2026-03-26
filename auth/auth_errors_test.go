// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthOptions_CustomHandlers(t *testing.T) {
	t.Run("OnGeneralError_Catchall", func(t *testing.T) {
		called := false
		opts := AuthErrorHandlers{
			OnGeneralError: func(w http.ResponseWriter, r *http.Request, err error) {
				called = true
				http.Error(w, "General Error", http.StatusTeapot)
			},
		}
		opts.ApplyGeneralError()

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		opts.OnUnauthorized(rr, req, fmt.Errorf("test error"))

		if !called {
			t.Error("OnGeneralError was not called")
		}
		if rr.Code != http.StatusTeapot {
			t.Errorf("Expected status %d, got %d", http.StatusTeapot, rr.Code)
		}
	})

	t.Run("SpecificHandlerTakesPrecedence", func(t *testing.T) {
		generalCalled := false
		specificCalled := false
		opts := AuthErrorHandlers{
			OnUnauthorized: func(w http.ResponseWriter, r *http.Request, err error) {
				specificCalled = true
				w.WriteHeader(http.StatusForbidden)
			},
			OnGeneralError: func(w http.ResponseWriter, r *http.Request, err error) {
				generalCalled = true
			},
		}
		opts.ApplyGeneralError()

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		opts.OnUnauthorized(rr, req, fmt.Errorf("test error"))

		if !specificCalled {
			t.Error("Specific handler was not called")
		}
		if generalCalled {
			t.Error("General handler should not have been called")
		}
		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
	})
}
