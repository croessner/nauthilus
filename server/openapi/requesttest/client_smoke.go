// Copyright (C) 2026 Christian Roessner
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

package requesttest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// ClientSmokeRoute describes the single generated-client request accepted by a
// smoke server.
type ClientSmokeRoute struct {
	Request      any
	Response     any
	ResponseBody []byte
	Headers      map[string]string
	ContentType  string
	Method       string
	Path         string
	Status       int
}

// ClientSmokeDoer handles generated-client requests without opening a socket.
type ClientSmokeDoer struct {
	t     testing.TB
	route ClientSmokeRoute
}

// NewClientSmokeDoer creates a focused in-memory doer for generated-client
// tests that should verify request construction and response parsing only.
func NewClientSmokeDoer(t testing.TB, route ClientSmokeRoute) *ClientSmokeDoer {
	t.Helper()

	return &ClientSmokeDoer{t: t, route: route}
}

// Do verifies the generated request and returns the configured response.
func (doer *ClientSmokeDoer) Do(request *http.Request) (*http.Response, error) {
	doer.t.Helper()

	assertSmokeRequest(doer.t, doer.route, request)

	response := httptest.NewRecorder()
	response.Header().Set("Content-Type", responseContentType(doer.route))
	response.WriteHeader(doer.route.Status)

	if doer.route.ResponseBody != nil {
		if _, err := response.Write(doer.route.ResponseBody); err != nil {
			doer.t.Fatalf("write generated-client smoke response: %v", err)
		}

		return response.Result(), nil
	}

	if doer.route.Response == nil {
		return response.Result(), nil
	}

	if err := json.NewEncoder(response).Encode(doer.route.Response); err != nil {
		doer.t.Fatalf("encode generated-client smoke response: %v", err)
	}

	return response.Result(), nil
}

func responseContentType(route ClientSmokeRoute) string {
	if route.ContentType != "" {
		return route.ContentType
	}

	return "application/json"
}

func assertSmokeRequest(t testing.TB, route ClientSmokeRoute, request *http.Request) {
	t.Helper()

	if request.Method != route.Method {
		t.Fatalf("request method = %q, want %q", request.Method, route.Method)
	}

	if request.URL.Path != route.Path {
		t.Fatalf("request path = %q, want %q", request.URL.Path, route.Path)
	}

	for name, want := range route.Headers {
		if got := request.Header.Get(name); got != want {
			t.Fatalf("request header %s = %q, want %q", name, got, want)
		}
	}

	if route.Request == nil {
		return
	}

	if contentType := request.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("request content type = %q, want application/json", contentType)
	}

	assertJSONBody(t, request, route.Request)
}

func assertJSONBody(t testing.TB, request *http.Request, want any) {
	t.Helper()

	var gotValue any
	if err := json.NewDecoder(request.Body).Decode(&gotValue); err != nil {
		t.Fatalf("decode generated-client smoke request body: %v", err)
	}

	var wantValue any

	wantBody, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal generated-client smoke request body: %v", err)
	}

	if err := json.Unmarshal(wantBody, &wantValue); err != nil {
		t.Fatalf("normalize generated-client smoke request body: %v", err)
	}

	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("request body = %#v, want %#v", gotValue, wantValue)
	}
}
