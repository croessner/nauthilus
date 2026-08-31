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

package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
)

func TestHTTPAuthInputBuilderPreservesRequestMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)

	builder := newHTTPAuthInputBuilder(applicationBoundaryDeps())

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(method, "/api/v1/auth/header", nil)

			got := builder.baseContext(ctx).Transport.HTTPMethod
			if got != method {
				t.Fatalf("transport HTTP method = %q, want %q", got, method)
			}
		})
	}
}

func TestHTTPAuthInputBuilderMapsGETStructuredLookupWithoutCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, service := range []string{definitions.ServJSON, definitions.ServCBOR} {
		t.Run(service, func(t *testing.T) {
			builder := newHTTPAuthInputBuilder(applicationBoundaryDeps())
			ctx, _ := newHTTPAuthAdapterTestContext(
				http.MethodGet,
				"/api/v1/auth/"+service+"?mode=no-auth",
				"",
				"",
				service,
			)

			input, structured, ok := builder.surfaceInput(ctx, service, core.AuthModeLookupIdentity)
			if !ok {
				t.Fatal("surfaceInput rejected GET lookup conversion")
			}

			if structured {
				t.Fatal("GET lookup unexpectedly reported a structured credential body")
			}

			if input.Credentials.Username != "" || !input.Credentials.Password.IsZero() {
				t.Fatal("GET lookup adapter invented credentials")
			}

			input.Context = mergeHTTPAuthContext(builder.baseContext(ctx), input.Context)
			if input.Context.Transport.HTTPMethod != http.MethodGet {
				t.Fatalf("transport HTTP method = %q, want GET", input.Context.Transport.HTTPMethod)
			}
		})
	}
}

func TestHTTPAuthInputBuilderAllowsGETStructuredLookupWithoutCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, service := range []string{definitions.ServJSON, definitions.ServCBOR} {
		t.Run(service, func(t *testing.T) {
			ctx, recorder := newHTTPAuthAdapterTestContext(
				http.MethodGet,
				"/api/v1/auth/"+service+"?mode=no-auth",
				"",
				"",
				service,
			)

			input, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx)
			if !ok {
				t.Fatalf("Build rejected legacy GET lookup with status %d", recorder.Code)
			}

			if input.Mode != core.AuthModeLookupIdentity || input.Context.Transport.HTTPMethod != http.MethodGet {
				t.Fatalf("mode/method = %q/%q, want lookup-identity/GET", input.Mode, input.Context.Transport.HTTPMethod)
			}

			if input.Credentials.Username != "" || !input.Credentials.Password.IsZero() {
				t.Fatal("GET lookup adapter invented credentials")
			}
		})
	}
}

func TestHTTPAuthInputBuilderMapsFormAndRemovesPassword(t *testing.T) {
	values := make(url.Values)
	values.Set("username", "alice")
	values.Set("realm", "example.test")
	values.Set("password", "form-password")
	values.Set("method", "PLAIN")
	values.Set("user_agent", "form-client/1.0")
	values.Set("port", "993")
	values.Set("protocol", definitions.ProtoIMAP)
	values.Set("tls", "on")
	values.Set("security", "TLSv1.3")

	ctx, recorder := newHTTPAuthAdapterTestContext(
		http.MethodPost,
		"/api/v1/auth/json",
		values.Encode(),
		"application/x-www-form-urlencoded",
		definitions.ServJSON,
	)

	input, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx)
	if !ok {
		t.Fatalf("Build rejected valid form input with status %d", recorder.Code)
	}

	assertHTTPAuthFormInput(t, input)
	assertHTTPAuthFormPasswordRemoved(t, ctx)
}

// assertHTTPAuthFormInput verifies the established form-to-application mapping.
func assertHTTPAuthFormInput(t *testing.T, input core.AuthInput) {
	t.Helper()

	if input.Credentials.Username != "alice@example.test" {
		t.Fatalf("username = %q, want alice@example.test", input.Credentials.Username)
	}

	input.Credentials.Password.WithString(func(value string) {
		if value != "form-password" {
			t.Fatalf("password = %q, want form password", value)
		}
	})

	if input.Context.Method != "PLAIN" || input.Context.UserAgent != "form-client/1.0" {
		t.Fatalf("method/user agent = %q/%q, want PLAIN/form-client/1.0", input.Context.Method, input.Context.UserAgent)
	}

	if input.Context.LocalIP != definitions.Localhost4 || input.Context.LocalPort != "993" {
		t.Fatalf("local endpoint = %q:%q, want %s:993", input.Context.LocalIP, input.Context.LocalPort, definitions.Localhost4)
	}

	if input.Context.Protocol != definitions.ProtoIMAP || input.Context.XSSL != "on" || input.Context.XSSLProtocol != "TLSv1.3" {
		t.Fatalf(
			"protocol/TLS = %q/%q/%q, want imap/on/TLSv1.3",
			input.Context.Protocol,
			input.Context.XSSL,
			input.Context.XSSLProtocol,
		)
	}
}

// assertHTTPAuthFormPasswordRemoved verifies that the adapter detaches consumed secrets.
func assertHTTPAuthFormPasswordRemoved(t *testing.T, ctx *gin.Context) {
	t.Helper()

	if ctx.Request.PostForm.Get("password") != "" || ctx.Request.Form.Get("password") != "" {
		t.Fatal("form password remained attached to the request")
	}
}

func TestHTTPAuthInputBuilderRejectsMalformedBodies(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "malformed JSON",
			contentType: "application/json",
			body:        `{"username":`,
		},
		{
			name:        "malformed CBOR",
			contentType: "application/cbor",
			body:        "\xff",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, recorder := newHTTPAuthAdapterTestContext(
				http.MethodPost,
				"/api/v1/auth/json",
				test.body,
				test.contentType,
				definitions.ServJSON,
			)

			if _, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx); ok {
				t.Fatal("Build accepted malformed request body")
			}

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("HTTP status = %d, want 400", recorder.Code)
			}
		})
	}
}

func TestHTTPAuthInputBuilderRejectsUnsupportedMediaType(t *testing.T) {
	ctx, recorder := newHTTPAuthAdapterTestContext(
		http.MethodPost,
		"/api/v1/auth/json",
		"username=alice%40example.test&password=secret",
		"text/plain",
		definitions.ServJSON,
	)

	if _, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx); ok {
		t.Fatal("Build accepted unsupported media type")
	}

	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), httpAuthUnsupportedMedia) {
		t.Fatalf("response = %d %q, want 400 with unsupported-media error", recorder.Code, recorder.Body.String())
	}
}

func TestHTTPAuthInputBuilderRejectsInvalidEncodedPassword(t *testing.T) {
	ctx, recorder := newHTTPAuthAdapterTestContext(
		http.MethodGet,
		"/api/v1/auth/header",
		"",
		"",
		definitions.ServHeader,
	)
	ctx.Request.Header.Set("Auth-User", "alice@example.test")
	ctx.Request.Header.Set("Auth-Pass", "*")
	ctx.Request.Header.Set("Auth-Pass-Encoded", "1")

	if _, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx); ok {
		t.Fatal("Build accepted invalid URL-safe base64 password")
	}

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("HTTP status = %d, want 400", recorder.Code)
	}

	if ctx.Request.Header.Get("Auth-Pass") != "" || ctx.Request.Header.Get("Auth-Pass-Encoded") != "" {
		t.Fatal("invalid credential headers remained attached to the request")
	}
}

func TestHTTPAuthInputBuilderPartiallyDecodesConfiguredHeaders(t *testing.T) {
	ctx, recorder := newHTTPAuthAdapterTestContext(
		http.MethodGet,
		"/api/v1/auth/header",
		"",
		"",
		definitions.ServHeader,
	)
	ctx.Request.Header.Set("Auth-User", "alice%40example.test")
	ctx.Request.Header.Set("Auth-Pass", "my%20pass%25word")
	ctx.Request.Header.Set("Auth-Protocol", "im%61p")
	ctx.Request.Header.Set("Auth-Method", "PL%41IN")

	input, ok := newHTTPAuthInputBuilder(applicationBoundaryDeps()).Build(ctx)
	if !ok {
		t.Fatalf("Build rejected partially encoded headers with status %d", recorder.Code)
	}

	if input.Credentials.Username != "alice@example.test" {
		t.Fatalf("username = %q, want decoded username", input.Credentials.Username)
	}

	input.Credentials.Password.WithString(func(value string) {
		if value != "my pass%word" {
			t.Fatalf("password = %q, want partially decoded password", value)
		}
	})

	if input.Context.Protocol != definitions.ProtoIMAP || input.Context.Method != "PLAIN" {
		t.Fatalf("protocol/method = %q/%q, want imap/PLAIN", input.Context.Protocol, input.Context.Method)
	}
}

func TestHTTPAuthInputBuilderHonorsForwardedClientOnlyFromTrustedPeer(t *testing.T) {
	tests := []struct {
		name         string
		remote       string
		clientHeader string
		forwardedFor string
		want         string
	}{
		{
			name:         "trusted configured client header",
			remote:       "192.0.2.10:4242",
			clientHeader: "203.0.113.10",
			forwardedFor: "198.51.100.10",
			want:         "203.0.113.10",
		},
		{
			name:         "trusted standard forwarded header",
			remote:       "192.0.2.10:4242",
			forwardedFor: "198.51.100.10",
			want:         "198.51.100.10",
		},
		{
			name:         "untrusted forwarded headers ignored",
			remote:       "198.51.100.20:4242",
			clientHeader: "203.0.113.10",
			forwardedFor: "203.0.113.11",
			want:         "198.51.100.20",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := applicationBoundaryDeps()
			settings := deps.Cfg.(*config.FileSettings)
			settings.Server.TrustedProxies = []string{"192.0.2.0/24"}

			ctx, _ := newHTTPAuthAdapterTestContext(
				http.MethodGet,
				"/api/v1/auth/header",
				"",
				"",
				definitions.ServHeader,
			)
			ctx.Request.RemoteAddr = test.remote
			ctx.Request.Header.Set("Client-IP", test.clientHeader)
			ctx.Request.Header.Set("X-Forwarded-For", test.forwardedFor)

			got := newHTTPAuthInputBuilder(deps).baseContext(ctx).ClientIP
			if got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

// newHTTPAuthAdapterTestContext constructs one detached request adapter context.
func newHTTPAuthAdapterTestContext(
	method string,
	target string,
	body string,
	contentType string,
	service string,
) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	ctx.Set(definitions.CtxServiceKey, service)
	ctx.Set(definitions.CtxGUIDKey, "request-adapter-test")

	if contentType != "" {
		ctx.Request.Header.Set("Content-Type", contentType)
	}

	return ctx, recorder
}
