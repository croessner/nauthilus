// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// TestHandleFile_FrontendEncryptionSecretNeedsEnvelopeKeyLength checks that the configuration rejects a frontend
// encryption secret the browser envelope codec cannot use. The codec needs 32 bytes, so the rule counts bytes, not
// characters.
func TestHandleFile_FrontendEncryptionSecretNeedsEnvelopeKeyLength(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{name: "16 ASCII characters", secret: strings.Repeat("a", 16), wantErr: true},
		{name: "31 ASCII characters", secret: strings.Repeat("a", 31), wantErr: true},
		{name: "32 ASCII characters", secret: strings.Repeat("a", 32), wantErr: false},
		{name: "16 two-byte characters", secret: strings.Repeat("ä", 16), wantErr: false},
		{name: "15 two-byte characters and one ASCII character", secret: strings.Repeat("ä", 15) + "a", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			viper.Set("storage", map[string]any{
				"redis": map[string]any{
					"primary": map[string]any{
						"address": "localhost:6379",
					},
					"password_nonce":    testRedisPasswordNonce,
					"encryption_secret": testRedisEncryptionSecret,
				},
			})
			viper.Set("identity", map[string]any{
				"frontend": map[string]any{
					"enabled":           true,
					"encryption_secret": tc.secret,
				},
			})

			err := (&FileSettings{}).HandleFile()

			if tc.wantErr {
				if err == nil {
					t.Fatal("HandleFile() error = nil, want rejection of the short frontend encryption secret")
				}

				if !strings.Contains(err.Error(), "secret_min_bytes") {
					t.Fatalf("HandleFile() error = %q, want the secret_min_bytes rule", err)
				}

				if strings.Contains(err.Error(), tc.secret) {
					t.Fatal("HandleFile() error discloses the secret value")
				}

				return
			}

			if err != nil && strings.Contains(err.Error(), "secret_min_bytes") {
				t.Fatalf("HandleFile() error = %q, want the secret accepted", err)
			}
		})
	}
}
