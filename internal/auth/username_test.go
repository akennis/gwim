// Copyright 2026 Albert Kennis. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth

import "testing"

func TestNormalizeUsername(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"TESTUSER@EXAMPLE.COM", "testuser"},
		{"DOMAIN\\testuser", "testuser"},
		{"testuser", "testuser"},
		{"TESTUSER", "testuser"},
		{"user.name@REALM", "user.name"},
		{"DOMAIN\\user.name", "user.name"},
		{"", ""},
		{"@realm", ""},
		{"domain\\", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeUsername(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeUsername(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
