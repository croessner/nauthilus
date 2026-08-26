// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package core

import (
	"net/http"
	"reflect"
	"testing"
)

func TestSanitizeHTTPMetadataDropsCredentialsAndDetachesSafeValues(t *testing.T) {
	headers := http.Header{
		"Authorization":       {"Bearer secret"},
		"Cookie":              {"session=secret"},
		"Proxy-Authorization": {"Basic secret"},
		"Set-Cookie":          {"response=secret"},
		"Auth-Pass":           {"password"},
		"Auth-Pass-Encoded":   {"1"},
		"X-Request-Id":        {"request-42"},
		" X-Tenant ":          {"example"},
		" ":                   {"ignored"},
	}

	metadata := SanitizeHTTPMetadata(headers, " Auth-Pass ", "AUTH-PASS-ENCODED")
	headers["X-Request-Id"][0] = "mutated"

	want := map[string][]string{
		"x-request-id": {"request-42"},
		"x-tenant":     {"example"},
	}
	if !reflect.DeepEqual(metadata, want) {
		t.Fatalf("sanitized metadata = %#v, want %#v", metadata, want)
	}
}

func TestSanitizeHTTPMetadataHandlesNilAndEmptyCredentialNames(t *testing.T) {
	if got := SanitizeHTTPMetadata(nil, "", "  "); got != nil {
		t.Fatalf("nil metadata = %#v, want nil", got)
	}

	metadata := SanitizeHTTPMetadata(http.Header{"X-Safe": {"value"}}, "", "  ")
	if !reflect.DeepEqual(metadata, map[string][]string{"x-safe": {"value"}}) {
		t.Fatalf("sanitized safe metadata = %#v", metadata)
	}
}
