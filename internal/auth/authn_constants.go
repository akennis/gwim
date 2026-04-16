// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

const (
	authorization   = "Authorization"
	negotiate       = "Negotiate"
	negotiateSpc    = negotiate + " "
	tokenOffset     = len(negotiateSpc)
	wwwAuthenticate = "WWW-Authenticate"
)
