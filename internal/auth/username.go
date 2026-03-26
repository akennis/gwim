// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import "strings"

// NormalizeUsername normalizes a username by stripping domain/realm suffixes
// and prefixes, and converting it to lowercase.
// It handles:
// - Kerberos/UPN formats: "user@REALM.COM" -> "user"
// - NTLM/NetBIOS formats: "DOMAIN\user" -> "user"
func NormalizeUsername(username string) string {
	if strings.Contains(username, "@") {
		username = strings.Split(username, "@")[0]
	} else if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		username = parts[len(parts)-1]
	}
	return strings.ToLower(username)
}
