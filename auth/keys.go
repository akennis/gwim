// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

type ContextKey string

const (
	ContextKeyUserGroups ContextKey = "userGroups"
	ContextKeyUsername   ContextKey = "username"
	ContextKeyConnID     ContextKey = "connId"
)
