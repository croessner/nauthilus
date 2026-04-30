// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"strings"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

func TestFormatDecodeErrors_UsesCanonicalConfigPaths(t *testing.T) {
	t.Helper()

	cfg := &FileSettings{}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		ErrorUnused:      true,
		Result:           cfg,
		WeaklyTypedInput: true,
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		t.Fatalf("NewDecoder() error = %v", err)
	}

	err = decoder.Decode(map[string]any{
		"identity": map[string]any{
			"session": map[string]any{
				"remember_me_ttl": map[string]any{
					"bad": true,
				},
			},
		},
	})
	if err == nil {
		t.Fatal("Decode() error = nil, want decode error")
	}

	formatted := formatDecodeErrors(err)
	if formatted == nil {
		t.Fatal("formatDecodeErrors() = nil, want formatted error")
	}

	if !strings.Contains(formatted.Error(), "identity.session.remember_me_ttl") {
		t.Fatalf("formatDecodeErrors() = %q, want canonical config path", formatted.Error())
	}
}

func TestFormatConfigProblems_UsesMultilineOutputForMultipleProblems(t *testing.T) {
	t.Helper()

	err := formatConfigProblems([]Problem{
		{
			Kind:    configProblemValidation,
			Path:    "runtime.servers.http.tls.cert",
			Message: "failed validation rule 'file'",
		},
		{
			Kind:    configProblemValidation,
			Path:    "auth.controls.lua.hooks[0].script_path",
			Message: "failed validation rule 'file'",
		},
	})
	if err == nil {
		t.Fatal("formatConfigProblems() = nil, want error")
	}

	got := err.Error()

	expectedParts := []string{
		"configuration errors:\n",
		"- field 'auth.controls.lua.hooks[0].script_path' failed validation rule 'file'\n",
		"- field 'runtime.servers.http.tls.cert' failed validation rule 'file'",
	}

	for _, expected := range expectedParts {
		if !strings.Contains(got, expected) {
			t.Fatalf("formatConfigProblems() = %q, want substring %q", got, expected)
		}
	}

	if strings.Contains(got, "; ") {
		t.Fatalf("formatConfigProblems() = %q, want multiline output without semicolon concatenation", got)
	}
}

func TestHandleFile_ValidationErrorsUseCanonicalPathsOnly(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setValidationErrorTestConfig()

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want validation error")
	}

	got := err.Error()

	assertContainsAll(t, got, []string{
		"runtime.servers.http.tls.cert",
		"runtime.servers.http.tls.key",
		"auth.controls.lua.hooks[0].script_path",
	})
	assertContainsNone(t, got, []string{
		"FileSettings.Server.TLS.Cert",
		"FileSettings.Server.TLS.Key",
		"FileSettings.Lua.Hooks[0].ScriptPath",
	})
}

func TestHandleFile_RejectsLegacyHTTPClientSkipVerify(t *testing.T) {
	t.Helper()

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
	viper.Set("runtime", map[string]any{
		"servers": map[string]any{
			"http": map[string]any{
				"tls": map[string]any{
					"http_client_skip_verify": true,
				},
			},
		},
	})

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want legacy field rejection")
	}

	got := err.Error()

	if !strings.Contains(got, "runtime.servers.http.tls") || !strings.Contains(got, "http_client_skip_verify") {
		t.Fatalf("HandleFile() error = %q, want canonical parent path plus rejected key", got)
	}
}

func TestHandleFile_RejectsRemovedRuntimeListenAndHTTPPaths(t *testing.T) {
	t.Helper()

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
	viper.Set("runtime", map[string]any{
		"listen": map[string]any{
			"address": "127.0.0.1:9080",
		},
		"http": map[string]any{
			"keep_alive": map[string]any{
				"enabled": true,
			},
		},
	})

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want removed runtime path rejection")
	}

	got := err.Error()
	assertContainsAll(t, got, []string{"runtime", "listen", "http"})
}

func TestHandleFile_RejectsEnabledGRPCAuthWithoutBackchannelAuth(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setGRPCAuthValidationTestConfig("127.0.0.1:9444")

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want gRPC backchannel auth configuration error")
	}

	got := err.Error()
	assertContainsAll(t, got, []string{
		"runtime.servers.grpc.auth.enabled",
		"auth.backchannel.basic_auth.enabled=true",
		"auth.backchannel.oidc_bearer.enabled=true",
	})
}

func TestHandleFile_RejectsPlaintextGRPCAuthOnNonLoopback(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setGRPCAuthValidationTestConfig("0.0.0.0:9444")
	viper.Set("auth", map[string]any{
		"backchannel": map[string]any{
			"basic_auth": map[string]any{
				"enabled":  true,
				"username": "grpc-test",
				"password": "grpc-secret-1234",
			},
		},
	})

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want plaintext gRPC bind validation error")
	}

	got := err.Error()
	assertContainsAll(t, got, []string{
		"runtime.servers.grpc.auth.address",
		"plaintext",
		"loopback",
	})
}

func TestHandleFile_RejectsGRPCAuthWithIncompleteBasicBackchannelAuth(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setGRPCAuthValidationTestConfig("127.0.0.1:9444")
	viper.Set("auth", map[string]any{
		"backchannel": map[string]any{
			"basic_auth": map[string]any{
				"enabled": true,
			},
		},
	})

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want incomplete gRPC Basic backchannel auth configuration error")
	}

	got := err.Error()
	assertContainsAll(t, got, []string{
		"auth.backchannel.basic_auth.username",
		"auth.backchannel.basic_auth.password",
	})
}

func TestHandleFile_RejectsGRPCAuthClientCertWithoutTLS(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	setGRPCAuthValidationTestConfig("127.0.0.1:9444")
	viper.Set("auth", map[string]any{
		"backchannel": map[string]any{
			"basic_auth": map[string]any{
				"enabled":  true,
				"username": "grpc-test",
				"password": "grpc-secret-1234",
			},
		},
	})
	viper.Set("runtime.servers.grpc.auth.tls.require_client_cert", true)

	cfg := &FileSettings{}
	err := cfg.HandleFile()
	if err == nil {
		t.Fatal("HandleFile() error = nil, want gRPC client certificate TLS configuration error")
	}

	got := err.Error()
	assertContainsAll(t, got, []string{
		"runtime.servers.grpc.auth.tls.require_client_cert",
		"runtime.servers.grpc.auth.tls.enabled",
	})
}

func setValidationErrorTestConfig() {
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
	viper.Set("runtime", map[string]any{
		"servers": map[string]any{
			"http": map[string]any{
				"tls": map[string]any{
					"cert": "/definitely/missing/cert.pem",
					"key":  "/definitely/missing/key.pem",
				},
			},
		},
	})
	viper.Set("auth", map[string]any{
		"controls": map[string]any{
			"lua": map[string]any{
				"hooks": []any{
					map[string]any{
						"http_location": "/test",
						"http_method":   "GET",
						"script_path":   "/definitely/missing/hook.lua",
					},
				},
			},
		},
	})
}

func setGRPCAuthValidationTestConfig(address string) {
	viper.Set("storage", map[string]any{
		"redis": map[string]any{
			"primary": map[string]any{
				"address": "localhost:6379",
			},
			"password_nonce":    testRedisPasswordNonce,
			"encryption_secret": testRedisEncryptionSecret,
		},
	})
	viper.Set("runtime", map[string]any{
		"servers": map[string]any{
			"grpc": map[string]any{
				"auth": map[string]any{
					"enabled": true,
					"address": address,
				},
			},
		},
	})
}

func assertContainsAll(t *testing.T, got string, expected []string) {
	t.Helper()

	for _, item := range expected {
		if !strings.Contains(got, item) {
			t.Fatalf("error = %q, want substring %q", got, item)
		}
	}
}

func assertContainsNone(t *testing.T, got string, unwanted []string) {
	t.Helper()

	for _, item := range unwanted {
		if strings.Contains(got, item) {
			t.Fatalf("error = %q, do not want substring %q", got, item)
		}
	}
}
