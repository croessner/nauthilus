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

package router

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/gin-gonic/gin"
)

func TestWithSecurityTxt_RegistersConfiguredEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "security-policy.md")
	keyPath := filepath.Join(dir, "security.asc")

	writeSecurityTxtTestFile(t, policyPath, []byte("# Security Policy\n"))
	writeSecurityTxtTestFile(t, keyPath, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"))

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			SecurityTxt: config.SecurityTxt{
				Enabled:            true,
				Contacts:           []string{"mailto:security@example.test", "https://example.test/security"},
				Expires:            "2026-12-31T23:59:00+01:00",
				Canonical:          []string{"https://example.test/.well-known/security.txt"},
				EncryptionFile:     keyPath,
				EncryptionURI:      "https://example.test/.well-known/security.asc",
				PolicyFile:         policyPath,
				PolicyURI:          "https://example.test/.well-known/security-policy",
				PreferredLanguages: []string{"en", "de"},
			},
		},
	}

	router := NewRouter(cfg).WithSecurityTxt().Build()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, securityTxtPath, nil)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", securityTxtPath, recorder.Code, http.StatusOK)
	}

	if contentType := recorder.Header().Get("Content-Type"); contentType != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/plain; charset=utf-8", contentType)
	}

	want := "Contact: mailto:security@example.test\n" +
		"Contact: https://example.test/security\n" +
		"Expires: 2026-12-31T22:59:00Z\n" +
		"Encryption: https://example.test/.well-known/security.asc\n" +
		"Preferred-Languages: en, de\n" +
		"Canonical: https://example.test/.well-known/security.txt\n" +
		"Policy: https://example.test/.well-known/security-policy\n"
	if recorder.Body.String() != want {
		t.Fatalf("security.txt body = %q, want %q", recorder.Body.String(), want)
	}
}

func TestWithSecurityTxt_ServesConfiguredFiles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "security-policy.md")
	keyPath := filepath.Join(dir, "security.asc")

	writeSecurityTxtTestFile(t, policyPath, []byte("# Security Policy\n"))
	writeSecurityTxtTestFile(t, keyPath, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"))

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			SecurityTxt: config.SecurityTxt{
				Enabled:        true,
				Contacts:       []string{"mailto:security@example.test"},
				ExpiresAfter:   time.Hour,
				EncryptionFile: keyPath,
				EncryptionURI:  "https://example.test/.well-known/security.asc",
				PolicyFile:     policyPath,
				PolicyURI:      "https://example.test/.well-known/security-policy",
			},
		},
	}

	router := NewRouter(cfg).WithSecurityTxt().Build()
	assertSecurityTxtFile(t, router, "/.well-known/security.asc", "application/pgp-keys", "PGP PUBLIC KEY")
	assertSecurityTxtFile(t, router, "/.well-known/security-policy", "text/markdown; charset=utf-8", "Security Policy")
}

func TestWithSecurityTxt_SkipsEndpointWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	router := NewRouter(cfg).WithSecurityTxt().Build()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, securityTxtPath, nil)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET %s status = %d, want %d", securityTxtPath, recorder.Code, http.StatusNotFound)
	}
}

func TestSecurityTxtRenderer_UsesDynamicExpiration(t *testing.T) {
	renderer := SecurityTxtRenderer{
		cfg: &config.SecurityTxt{
			Enabled:      true,
			Contacts:     []string{"mailto:security@example.test"},
			ExpiresAfter: 2 * time.Hour,
		},
		now: func() time.Time {
			return time.Date(2026, time.April, 29, 10, 0, 0, 0, time.UTC)
		},
	}

	want := "Contact: mailto:security@example.test\nExpires: 2026-04-29T12:00:00Z\n"
	if got := renderer.Render(); got != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}
}

func assertSecurityTxtFile(t *testing.T, router http.Handler, path string, contentType string, bodySubstring string) {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
	}

	if got := recorder.Header().Get("Content-Type"); got != contentType {
		t.Fatalf("GET %s Content-Type = %q, want %q", path, got, contentType)
	}

	if !strings.Contains(recorder.Body.String(), bodySubstring) {
		t.Fatalf("GET %s body = %q, want substring %q", path, recorder.Body.String(), bodySubstring)
	}
}

func writeSecurityTxtTestFile(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}
