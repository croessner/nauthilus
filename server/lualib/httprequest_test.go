// Copyright (C) 2024 Christian Rößner
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

package lualib

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yuin/gopher-lua"
)

const testHTTPRequestBodyLimit = 1 << 20

func bindTestHTTPRequestMeta(L *lua.LState, request *http.Request) {
	reqEnv := L.NewTable()
	L.SetGlobal(luaRequestEnvKey, reqEnv)

	bindRequestValue(L, reqEnv, luaHTTPRequestMetaKey, NewHTTPMetaFromRequest(request))
}

func TestGetAllHTTPRequestHeaders(t *testing.T) {
	for _, tc := range allHTTPRequestHeaderCases() {
		t.Run(tc.name, func(t *testing.T) {
			lTable := executeAllHTTPRequestHeaders(t, tc.requestHeaders)
			assertLuaTableKeys(t, lTable, tc.expectedKeys)
		})
	}
}

type allHTTPRequestHeaderCase struct {
	name           string
	requestHeaders http.Header
	expectedKeys   []string
}

// allHTTPRequestHeaderCases returns coverage for full header extraction.
func allHTTPRequestHeaderCases() []allHTTPRequestHeaderCase {
	return []allHTTPRequestHeaderCase{
		{
			name: "AllHeadersSingleValue",
			requestHeaders: http.Header{
				"Accept":        []string{"application/json"},
				"Authorization": []string{"Bearer abc123"},
				"Cookie":        []string{"session_id=123456"},
			},
			expectedKeys: []string{"accept", "authorization", "cookie"},
		},
		{
			name: "AllHeadersMultipleValues",
			requestHeaders: http.Header{
				"Cache-Control": []string{"no-cache", "no-store"},
				"Accept":        []string{"application/json", "text/html"},
			},
			expectedKeys: []string{"cache-control", "accept"},
		},
		{
			name:           "EmptyHeaders",
			requestHeaders: http.Header{},
			expectedKeys:   []string{},
		},
	}
}

// executeAllHTTPRequestHeaders runs the Lua binding and returns the header table.
func executeAllHTTPRequestHeaders(t *testing.T, headers http.Header) *lua.LTable {
	t.Helper()

	L := lua.NewState()
	t.Cleanup(L.Close)

	bindTestHTTPRequestMeta(L, &http.Request{Header: headers})

	manager := NewHTTPRequestManager()
	manager.GetAllHTTPRequestHeaders(L)

	return requireHTTPRequestResultTable(t, L)
}

func TestGetHTTPRequestHeader(t *testing.T) {
	for _, tc := range httpRequestHeaderCases() {
		t.Run(tc.name, func(t *testing.T) {
			lTable := executeHTTPRequestHeader(t, tc.requestHeaders, tc.headerToGet)
			assertLuaTableValues(t, lTable, tc.expectedValues)
		})
	}
}

type httpRequestHeaderCase struct {
	name           string
	requestHeaders http.Header
	headerToGet    string
	expectedValues []string
}

// httpRequestHeaderCases returns coverage for named header extraction.
func httpRequestHeaderCases() []httpRequestHeaderCase {
	return []httpRequestHeaderCase{
		{
			name: "SingleHeaderSingleValue",
			requestHeaders: http.Header{
				"Accept": []string{"application/json"},
			},
			headerToGet:    "accept",
			expectedValues: []string{"application/json"},
		},
		{
			name: "SingleHeaderMultipleValues",
			requestHeaders: http.Header{
				"Accept-Language": []string{"en-US", "fr-CA"},
			},
			headerToGet:    "accept-language",
			expectedValues: []string{"en-US", "fr-CA"},
		},
		{
			name: "MultipleHeaders",
			requestHeaders: http.Header{
				"Content-Type":   []string{"application/json"},
				"Content-Length": []string{"123"},
			},
			headerToGet:    "content-length",
			expectedValues: []string{"123"},
		},
		{
			name: "NonExistentHeader",
			requestHeaders: http.Header{
				"Cookie": []string{"session_id=123456"},
			},
			headerToGet:    "authorization",
			expectedValues: []string{},
		},
	}
}

// executeHTTPRequestHeader runs the Lua binding for one header name.
func executeHTTPRequestHeader(t *testing.T, headers http.Header, headerToGet string) *lua.LTable {
	t.Helper()

	L := lua.NewState()
	t.Cleanup(L.Close)

	L.Push(lua.LString(headerToGet))
	bindTestHTTPRequestMeta(L, &http.Request{Header: headers})

	manager := NewHTTPRequestManager()
	manager.GetHTTPRequestHeader(L)

	return requireHTTPRequestResultTable(t, L)
}

func TestGetHTTPRequestBodyRejectsOversizedBody(t *testing.T) {
	L := lua.NewState()
	t.Cleanup(L.Close)

	req, err := http.NewRequest(http.MethodPost, "/custom/hook", strings.NewReader(strings.Repeat("x", testHTTPRequestBodyLimit+1)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	bindTestHTTPRequestMeta(L, req)

	manager := NewHTTPRequestManager()
	manager.GetHTTPRequestBody(L)

	if got := L.Get(-2); got != lua.LNil {
		t.Fatalf("body result type=%s len=%d, want nil for oversized request", got.Type().String(), len(got.String()))
	}

	gotErr := L.Get(-1)

	if gotErr == lua.LNil {
		t.Fatal("error result is nil, want explicit body limit error")
	}

	if !strings.Contains(gotErr.String(), "request body too large") {
		t.Fatalf("error = %q, want explicit body limit error", gotErr.String())
	}
}

func TestGetHTTPRequestBodyReplaysAllowedBody(t *testing.T) {
	L := lua.NewState()
	t.Cleanup(L.Close)

	req, err := http.NewRequest(http.MethodPost, "/custom/hook", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	bindTestHTTPRequestMeta(L, req)

	manager := NewHTTPRequestManager()
	for i := 0; i < 2; i++ {
		manager.GetHTTPRequestBody(L)
		assertHTTPRequestBodyResult(t, L, "payload")
	}

	replayed, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read replayed body: %v", err)
	}

	if string(replayed) != "payload" {
		t.Fatalf("replayed body = %q, want payload", string(replayed))
	}
}

// assertHTTPRequestBodyResult verifies one Lua body result pair.
func assertHTTPRequestBodyResult(t *testing.T, L *lua.LState, want string) {
	t.Helper()

	gotErr := L.Get(-1)
	if gotErr != lua.LNil {
		t.Fatalf("error result = %v, want nil", gotErr)
	}

	got := L.Get(-2)
	if got.String() != want {
		t.Fatalf("body result = %q, want %q", got.String(), want)
	}

	L.Pop(2)
}

// requireHTTPRequestResultTable returns the Lua table and asserts a nil error result.
func requireHTTPRequestResultTable(t *testing.T, L *lua.LState) *lua.LTable {
	t.Helper()

	lTable := L.CheckTable(-2)

	lError := L.Get(-1)
	if lError != lua.LNil {
		t.Errorf("Expected nil error but got %v", lError)
	}

	return lTable
}

// assertLuaTableKeys verifies that a Lua table contains exactly the expected keys.
func assertLuaTableKeys(t *testing.T, lTable *lua.LTable, expectedKeys []string) {
	t.Helper()

	foundKeys := make(map[string]bool)

	lTable.ForEach(func(k, _ lua.LValue) {
		key := fmt.Sprintf("%v", k)
		foundKeys[key] = true
	})

	assertStringSet(t, "header key", foundKeys, expectedKeys, luaTableEntryCount(lTable))
}

// assertLuaTableValues verifies that a Lua table contains exactly the expected values.
func assertLuaTableValues(t *testing.T, lTable *lua.LTable, expectedValues []string) {
	t.Helper()

	foundValues := make(map[string]bool)

	lTable.ForEach(func(_, v lua.LValue) {
		value := fmt.Sprintf("%v", v)
		foundValues[value] = true
	})

	assertStringSet(t, "header value", foundValues, expectedValues, lTable.Len())
}

// assertStringSet verifies that all expected strings were discovered in a Lua result table.
func assertStringSet(t *testing.T, label string, found map[string]bool, expected []string, gotCount int) {
	t.Helper()

	if len(expected) != gotCount {
		t.Errorf("expected number of %ss to be %d, got %d", label, len(expected), gotCount)
	}

	for _, value := range expected {
		if !found[value] {
			t.Errorf("expected %s %s was not found", label, value)
		}
	}
}

// luaTableEntryCount counts all entries because LTable.Len only covers sequence values.
func luaTableEntryCount(lTable *lua.LTable) int {
	count := 0

	lTable.ForEach(func(_ lua.LValue, _ lua.LValue) {
		count++
	})

	return count
}

func TestURLPartialDecode(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "DecodePercentAndSpace",
			input: "my%20pass%25word",
			want:  "my pass%word",
		},
		{
			name:  "LeavePlusAsIs",
			input: "pass+word%2Bnext",
			want:  "pass+word+next",
		},
		{
			name:  "InvalidEscapeRemains",
			input: "abc%2Gdef",
			want:  "abc%2Gdef",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()

			L.Push(lua.LString(tc.input))

			manager := NewHTTPRequestManager()
			manager.URLPartialDecode(L)

			got := L.Get(-2)
			errVal := L.Get(-1)

			if errVal != lua.LNil {
				t.Fatalf("expected nil error, got %v", errVal)
			}

			if got.String() != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got.String())
			}
		})
	}
}
