// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

const (
	AUTHORIZATION = "Authorization"
	NEGOTIATE     = "Negotiate"
	NEGOTIATE_SPC = NEGOTIATE + " "
	TOKEN_OFFSET  = len(NEGOTIATE_SPC)
	WWW_AUTH      = "WWW-Authenticate"
)
