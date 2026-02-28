// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

// contextKey is an unexported type for context keys in this package.
// Using an unexported type prevents external packages from creating colliding
// keys, even though the constant values themselves are exported.
type contextKey string

const (
	ContextKeyUserGroups contextKey = "userGroups"
	ContextKeyUsername   contextKey = "username"
	ContextKeyConnID     contextKey = "connId"
)
