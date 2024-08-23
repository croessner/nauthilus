package lualib

import (
	"fmt"
	"net/http"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

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

			lFunc := GetHTTPRequestHeader(httpRequest)
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
