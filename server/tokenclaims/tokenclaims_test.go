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

package tokenclaims

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/golang-jwt/jwt/v5"
)

const mcpResource = "https://login.example.test/mcp"

// TestHasExactAudienceSet pins that a token granted for a second resource never matches the exact set of a
// resource server, which blocks cross-resource replay.
func TestHasExactAudienceSet(t *testing.T) {
	for name, tc := range map[string]struct {
		audience any
		want     bool
	}{
		"exact pair":              {[]any{"cli", mcpResource}, true},
		"exact pair other order":  {[]any{mcpResource, "cli"}, true},
		"duplicate value":         {[]any{"cli", mcpResource, mcpResource}, true},
		"additional resource":     {[]any{"cli", mcpResource, "https://mail.example.test/"}, false},
		"client only":             {"cli", false},
		"resource only":           {mcpResource, false},
		"padded value":            {[]any{"cli", " " + mcpResource}, false},
		"empty value":             {[]any{"cli", mcpResource, ""}, false},
		"missing audience":        {nil, false},
		"wrong type in the array": {[]any{"cli", 7}, false},
	} {
		t.Run(name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			if tc.audience != nil {
				claims["aud"] = tc.audience
			}

			if got := HasExactAudienceSet(claims, "cli", mcpResource); got != tc.want {
				t.Fatalf("HasExactAudienceSet() = %v, want %v", got, tc.want)
			}
		})
	}

	if HasExactAudienceSet(jwt.MapClaims{"aud": "cli"}) || HasExactAudienceSet(jwt.MapClaims{"aud": "cli"}, "") {
		t.Fatal("an empty expectation must never match")
	}
}

// TestScopeAndTypePredicates pins exact scope tokens and the token type check.
func TestScopeAndTypePredicates(t *testing.T) {
	claims := jwt.MapClaims{"scope": "nauthilus:history_read  openid", definitions.ClaimTokenType: definitions.TokenTypeAccessToken}

	if !HasScope(claims, "openid") || HasScope(claims, "nauthilus:history") || HasScope(claims, "") {
		t.Fatal("HasScope must match whole scope tokens only")
	}

	if !HasAnyScope(claims, "x", "nauthilus:history_read") || HasAnyScope(claims, "x", "y") {
		t.Fatal("HasAnyScope mismatch")
	}

	if got := Scopes(claims); !slices.Equal(got, []string{"nauthilus:history_read", "openid"}) {
		t.Fatalf("Scopes() = %v", got)
	}

	if !HasTokenType(claims, definitions.TokenTypeAccessToken) || HasTokenType(claims, "id_token") ||
		HasTokenType(jwt.MapClaims{}, definitions.TokenTypeAccessToken) {
		t.Fatal("HasTokenType mismatch")
	}
}

// TestNumericDate pins that JWT and opaque-session date encodings decode alike and malformed values fail.
func TestNumericDate(t *testing.T) {
	for name, tc := range map[string]struct {
		value   any
		present bool
		ok      bool
	}{
		"float64":     {float64(1_800_000_000), true, true},
		"int64":       {int64(1_800_000_000), true, true},
		"int":         {1_800_000_000, true, true},
		"json number": {json.Number("1800000000"), true, true},
		"bad number":  {json.Number("x"), true, false},
		"string":      {"1800000000", true, false},
		"zero":        {float64(0), true, false},
		"negative":    {int64(-1), true, false},
	} {
		t.Run(name, func(t *testing.T) {
			value, present, ok := NumericDate(jwt.MapClaims{"exp": tc.value}, "exp")
			if present != tc.present || ok != tc.ok {
				t.Fatalf("NumericDate() present=%v ok=%v, want %v %v", present, ok, tc.present, tc.ok)
			}

			if ok && value.Unix() != 1_800_000_000 {
				t.Fatalf("NumericDate() = %v", value)
			}
		})
	}

	if _, present, _ := NumericDate(jwt.MapClaims{}, "exp"); present {
		t.Fatal("a missing claim must not be present")
	}
}
