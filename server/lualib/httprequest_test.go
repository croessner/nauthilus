package lualib

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/yuin/gopher-lua"
)

func TestGetAllHTTPRequestHeaders(t *testing.T) {
	testCases := []struct {
		name           string
		requestHeaders http.Header
		expectedKeys   []string
	}{
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
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			httpRequest := &http.Request{
				Header: tc.requestHeaders,
			}

			lFunc := GetAllHTTPRequestHeaders(NewHTTPMetaFromRequest(httpRequest))
			lFunc(L)

			lTable := L.CheckTable(-1)

			lengthTable := 0
			lTable.ForEach(func(_ lua.LValue, _ lua.LValue) {
				lengthTable++
			})

			if len(tc.expectedKeys) != lengthTable {
				t.Errorf("expected number of header keys to be %d, got %d", len(tc.expectedKeys), lTable.Len())
			}

			foundKeys := make(map[string]bool)

			lTable.ForEach(func(k, _ lua.LValue) {
				key := fmt.Sprintf("%v", k)
				foundKeys[key] = true
			})

			for _, ek := range tc.expectedKeys {
				if !foundKeys[ek] {
					t.Errorf("expected header key %s was not found", ek)
				}
			}
		})
	}
}

func TestGetHTTPRequestHeader(t *testing.T) {
	testCases := []struct {
		name           string
		requestHeaders http.Header
		headerToGet    string
		expectedValues []string
	}{
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()

			defer L.Close()

			L.Push(lua.LString(tc.headerToGet))

			httpRequest := &http.Request{
				Header: tc.requestHeaders,
			}

			lFunc := GetHTTPRequestHeader(NewHTTPMetaFromRequest(httpRequest))
			lFunc(L)

			lTable := L.CheckTable(-1)

			if len(tc.expectedValues) != lTable.Len() {
				t.Errorf("expected number of header values to be %d, got %d", len(tc.expectedValues), lTable.Len())
			}

			foundValues := make(map[string]bool)

			lTable.ForEach(func(_, v lua.LValue) {
				value := fmt.Sprintf("%v", v)
				foundValues[value] = true
			})

			for _, ev := range tc.expectedValues {
				if !foundValues[ev] {
					t.Errorf("expected header value %s was not found", ev)
				}
			}
		})
	}
}
