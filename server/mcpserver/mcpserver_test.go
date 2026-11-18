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

package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	nautherrors "github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/supportapi"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	testResource = "https://login.example.test/mcp"
	testIssuer   = "https://login.example.test"
	testHost     = "login.example.test"
	testProxy    = "192.0.2.10"
	staticClient = "support-cli"
)

// fakeAuthority is a token authority with fixed tokens and clients.
type fakeAuthority struct {
	tokens      map[string]idp.UserAccessToken
	clients     map[string]*config.OIDCClient
	hosted      config.OIDCHostedResource
	unavailable bool
}

// ValidateUserAccessToken answers the fixed token table.
func (f *fakeAuthority) ValidateUserAccessToken(_ context.Context, token string) (idp.UserAccessToken, error) {
	if f.unavailable {
		return idp.UserAccessToken{}, nautherrors.NewTokenValidationUnavailable(errors.New("redis down"))
	}

	verified, ok := f.tokens[token]
	if !ok {
		return idp.UserAccessToken{}, idp.ErrNotUserAccessToken
	}

	return verified, nil
}

// ResolveClient answers the fixed client table.
func (f *fakeAuthority) ResolveClient(_ context.Context, clientID string) (*config.OIDCClient, error) {
	client, ok := f.clients[clientID]
	if !ok {
		return nil, errors.New("unknown client")
	}

	return client, nil
}

// HostedResource returns the one configured hosted resource.
func (f *fakeAuthority) HostedResource(name string) (idp.HostedResource, bool) {
	if name != f.hosted.Name {
		return idp.HostedResource{}, false
	}

	return idp.NewHostedResource(&f.hosted)
}

// Issuer returns the fixed issuer.
func (f *fakeAuthority) Issuer() string { return testIssuer }

// userToken returns a verified user token for the client with the given audience and scopes.
func userToken(clientID string, audience []any, scopes ...string) idp.UserAccessToken {
	return idp.UserAccessToken{Claims: jwt.MapClaims{"aud": audience}, ClientID: clientID, Subject: "anna-id",
		Scopes: scopes, Issuer: testIssuer, ExpiresAt: time.Now().Add(10 * time.Minute)}
}

// newAuthority returns the authority with the standard token table.
func newAuthority() *fakeAuthority {
	pair := []any{staticClient, testResource}

	return &fakeAuthority{
		hosted: config.OIDCHostedResource{Name: "support-mcp", Resource: testResource, StaticClients: []string{staticClient},
			Scopes: []string{definitions.ScopeHistoryRead, definitions.ScopeHistoryDetail, definitions.ScopeOperationsRead}},
		clients: map[string]*config.OIDCClient{
			staticClient:   {ClientID: staticClient},
			"other-static": {ClientID: "other-static"},
			"dcr_abc":      {ClientID: "dcr_abc", Dynamic: true},
		},
		tokens: map[string]idp.UserAccessToken{
			"good":           userToken(staticClient, pair, definitions.ScopeHistoryRead, definitions.ScopeOperationsRead),
			"history-only":   userToken(staticClient, pair, definitions.ScopeHistoryRead),
			"no-scope":       userToken(staticClient, pair, "openid"),
			"wrong-audience": userToken(staticClient, []any{staticClient, "https://mail.example.test/"}, definitions.ScopeHistoryRead),
			"extra-audience": userToken(staticClient, []any{staticClient, testResource, "https://mail.example.test/"}, definitions.ScopeHistoryRead),
			"client-only":    userToken(staticClient, []any{staticClient}, definitions.ScopeHistoryRead),
			"unlisted":       userToken("other-static", []any{"other-static", testResource}, definitions.ScopeHistoryRead),
			"dynamic":        userToken("dcr_abc", []any{"dcr_abc", testResource}, definitions.ScopeHistoryRead),
		},
	}
}

// fixedSource is an operations source with one fixed finding.
type fixedSource struct{}

// Name returns the runtime source name.
func (fixedSource) Name() string { return supportops.SourceRuntime }

// Kind returns the runtime kind.
func (fixedSource) Kind() supportops.SourceKind { return supportops.SourceKindLocalCurrent }

// Collect returns one fixed LDAP finding.
func (fixedSource) Collect(_ context.Context, query supportops.Query) supportops.SourceResult {
	return supportops.SourceResult{Report: supportops.SourceReport{Status: supportops.SourceStatusOK},
		Findings: []supportops.Finding{{Component: supportops.ComponentLDAP, Source: supportops.SourceRuntime, Status: supportops.StatusOK,
			Scope:     supportops.FindingScope{Kind: supportops.ScopeInstance, Instance: query.Instance},
			Freshness: supportops.Freshness{Basis: supportops.BasisCurrentState, ObservedAt: query.Now}}}}
}

// testServices returns services with a fixed operations source and no history.
func testServices(t *testing.T) supportapi.Services {
	t.Helper()

	operations, err := supportops.NewService(supportops.Options{Sources: []supportops.Source{fixedSource{}}, Instance: "mx-1",
		Now: func() time.Time { return time.Date(2026, time.November, 18, 8, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}

	return supportapi.Services{Operations: operations}
}

// newTestServer builds the endpoint over the fake authority.
func newTestServer(t *testing.T, authority *fakeAuthority, adjust func(*config.RuntimeMCPServerSection)) *Server {
	t.Helper()

	settings := &config.RuntimeMCPServerSection{Enabled: true, HostedResource: "support-mcp", TrustedProxies: []string{testProxy + "/32"},
		Limits: config.MCPLimits{FailedAuthPerMinute: 3}}
	if adjust != nil {
		adjust(settings)
	}

	server, err := New(Deps{Settings: settings, Tokens: authority, Services: testServices(t), Version: "test"})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	return server
}

// proxied returns a request as forwarded by the trusted TLS proxy.
func proxied(method string, path string, body string, token string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = testProxy + ":40000"
	request.Host = testHost
	request.Header.Set(headerForwardedProto, "https")
	request.Header.Set(headerForwardedFor, "203.0.113.7")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")

	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	return request
}

// serve runs one request against the endpoint.
func serve(server *Server, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	return recorder
}

// toolCall renders a tools/call JSON-RPC request.
func toolCall(name string, arguments string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
}

// TestTransportGuard pins the TLS-proxy boundary, the Host allowlist, the Origin deny gate, and the method filter.
func TestTransportGuard(t *testing.T) {
	server := newTestServer(t, newAuthority(), nil)

	for name, tc := range map[string]struct {
		mutate func(*http.Request)
		status int
	}{
		"direct untrusted peer": {func(r *http.Request) { r.RemoteAddr = "198.51.100.1:5000" }, http.StatusForbidden},
		"proxy without https":   {func(r *http.Request) { r.Header.Set(headerForwardedProto, "http") }, http.StatusForbidden},
		"foreign host":          {func(r *http.Request) { r.Host = "evil.example.test" }, http.StatusForbidden},
		"foreign origin":        {func(r *http.Request) { r.Header.Set(headerOrigin, "https://evil.example.test") }, http.StatusForbidden},
		"options method":        {func(r *http.Request) { r.Method = http.MethodOptions }, http.StatusMethodNotAllowed},
		"accepted transport":    {func(*http.Request) {}, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			request := proxied(http.MethodPost, "/mcp", `{}`, "")
			tc.mutate(request)

			if recorder := serve(server, request); recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}
		})
	}

	if serve(server, proxied(http.MethodGet, "/other", "", "good")).Code != http.StatusNotFound {
		t.Fatal("unknown paths must not be served")
	}
}

// TestForwardedClientIgnoresSpoofedHops pins that only the right-most untrusted X-Forwarded-For hop is the client, that
// hops may carry ports, and that a chain without a parsable client hop is refused instead of collapsing into the proxy.
func TestForwardedClientIgnoresSpoofedHops(t *testing.T) {
	server := newTestServer(t, newAuthority(), func(s *config.RuntimeMCPServerSection) {
		s.TrustedProxies = []string{testProxy + "/32", "10.0.0.0/8"}
	})

	for name, tc := range map[string]struct {
		values []string
		want   string
		ok     bool
	}{
		"spoofed left hop": {[]string{"1.2.3.4, 203.0.113.7"}, "203.0.113.7", true},
		"internal hops":    {[]string{"203.0.113.7, 10.1.1.1", "10.2.2.2"}, "203.0.113.7", true},
		"hop with port":    {[]string{"203.0.113.7:51234"}, "203.0.113.7", true},
		"ipv6 with port":   {[]string{"[2001:db8::7]:443"}, "2001:db8::7", true},
		"garbage hop":      {[]string{"203.0.113.7, not-an-ip"}, "", false},
		"only proxies":     {[]string{"10.1.1.1"}, "", false},
		"no header":        {nil, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := server.forwardedClient(tc.values)
			if ok != tc.ok || (ok && got.String() != tc.want) {
				t.Fatalf("forwardedClient() = %s %v, want %s %v", got, ok, tc.want, tc.ok)
			}
		})
	}

	request := proxied(http.MethodPost, "/mcp", `{}`, "")
	request.Header.Del(headerForwardedFor)

	if code := serve(server, request).Code; code != http.StatusForbidden {
		t.Fatalf("a trusted proxy request without client hop = %d, want 403", code)
	}

	request = proxied(http.MethodPost, "/mcp", `{}`, "")
	request.Header.Add(headerOrigin, "https://a.example.test")
	request.Header.Add(headerOrigin, "https://b.example.test")

	if code := serve(server, request).Code; code != http.StatusForbidden {
		t.Fatalf("multiple Origin headers = %d, want 403", code)
	}
}

// TestBearerVerificationMatrix pins 401/403/503 and the RFC 6750/9728 challenges for every rejected token class.
func TestBearerVerificationMatrix(t *testing.T) {
	authority := newAuthority()
	server := newTestServer(t, authority, func(s *config.RuntimeMCPServerSection) { s.Limits.FailedAuthPerMinute = 100 })
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

	for name, tc := range map[string]struct {
		token     string
		status    int
		challenge string
	}{
		"missing token":        {"", http.StatusUnauthorized, ""},
		"unknown or id token":  {"id-token", http.StatusUnauthorized, errorInvalidToken},
		"wrong audience":       {"wrong-audience", http.StatusUnauthorized, errorInvalidToken},
		"additional audience":  {"extra-audience", http.StatusUnauthorized, errorInvalidToken},
		"client audience only": {"client-only", http.StatusUnauthorized, errorInvalidToken},
		"unlisted static":      {"unlisted", http.StatusUnauthorized, errorInvalidToken},
		"dynamic client":       {"dynamic", http.StatusUnauthorized, errorInvalidToken},
		"no resource scope":    {"no-scope", http.StatusForbidden, errorInsufficientScope},
		"accepted":             {"good", http.StatusOK, ""},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := serve(server, proxied(http.MethodPost, "/mcp", initialize, tc.token))
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			if tc.status == http.StatusOK {
				return
			}

			header := recorder.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(header, "Bearer ") ||
				!strings.Contains(header, `resource_metadata="https://login.example.test/.well-known/oauth-protected-resource/mcp"`) ||
				!strings.Contains(header, `scope="nauthilus:history_read nauthilus:history_detail nauthilus:operations_read"`) ||
				(tc.challenge != "" && !strings.Contains(header, `error="`+tc.challenge+`"`)) {
				t.Fatalf("WWW-Authenticate = %q", header)
			}
		})
	}

	authority.unavailable = true

	if recorder := serve(server, proxied(http.MethodPost, "/mcp", initialize, "good")); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable authority = %d", recorder.Code)
	}
}

// TestFailedBearerLimiter pins the per-client-IP failure bound and that discovery probes are free.
func TestFailedBearerLimiter(t *testing.T) {
	server := newTestServer(t, newAuthority(), nil)

	for range 5 {
		serve(server, proxied(http.MethodPost, "/mcp", `{}`, ""))
	}

	for attempt := range 3 {
		if code := serve(server, proxied(http.MethodPost, "/mcp", `{}`, "forged")).Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", attempt, code)
		}
	}

	if code := serve(server, proxied(http.MethodPost, "/mcp", `{}`, "good")).Code; code != http.StatusTooManyRequests {
		t.Fatalf("after the limit = %d, want 429 even for a valid token", code)
	}

	other := proxied(http.MethodPost, "/mcp", `{}`, "forged")
	other.Header.Set(headerForwardedFor, "203.0.113.8")

	if code := serve(server, other).Code; code != http.StatusUnauthorized {
		t.Fatalf("another client = %d, want 401", code)
	}

	limiter := newFailureLimiter(1, time.Minute, func() time.Time { return time.Unix(0, 0) })
	client := netip.MustParseAddr("203.0.113.9")
	limiter.fail(client)

	if !limiter.blocked(client) {
		t.Fatal("limiter must block after the limit")
	}

	limiter.now = func() time.Time { return time.Unix(61, 0) }

	if limiter.blocked(client) {
		t.Fatal("limiter must reset after the window")
	}
}

// TestFailedBearerLimiterKeysAndCapacity pins IPv6 accounting per /64 and that a full table of live windows never
// blocks an untracked client.
func TestFailedBearerLimiterKeysAndCapacity(t *testing.T) {
	limiter := newFailureLimiter(1, time.Minute, func() time.Time { return time.Unix(0, 0) })
	limiter.fail(netip.MustParseAddr("2001:db8:1:2::1"))

	if !limiter.blocked(netip.MustParseAddr("2001:db8:1:2:ffff::9")) {
		t.Fatal("addresses of one IPv6 /64 must share one window")
	}

	if limiter.blocked(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("another /64 must not be blocked")
	}

	full := newFailureLimiter(1, time.Minute, func() time.Time { return time.Unix(0, 0) })
	for index := range maxTrackedClients {
		full.fail(netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)}))
	}

	stranger := netip.MustParseAddr("198.51.100.77")
	full.fail(stranger)

	if full.blocked(stranger) || len(full.entries) != maxTrackedClients {
		t.Fatalf("a full table must stop tracking new clients instead of blocking them (entries=%d)", len(full.entries))
	}

	if !full.blocked(netip.AddrFrom4([4]byte{10, 0, 0, 1})) {
		t.Fatal("tracked clients stay limited while the table is full")
	}
}

// TestProtectedResourceMetadata pins the RFC 9728 document at both locations.
func TestProtectedResourceMetadata(t *testing.T) {
	server := newTestServer(t, newAuthority(), nil)

	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		recorder := serve(server, proxied(http.MethodGet, path, "", ""))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, recorder.Code)
		}

		var document struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			Scopes               []string `json:"scopes_supported"`
			BearerMethods        []string `json:"bearer_methods_supported"`
		}

		if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
			t.Fatal(err)
		}

		if document.Resource != testResource || !slices.Equal(document.AuthorizationServers, []string{testIssuer}) ||
			len(document.Scopes) != 3 || !slices.Equal(document.BearerMethods, []string{"header"}) {
			t.Fatalf("%s = %+v", path, document)
		}
	}
}

// TestBodyInspection pins the refusals before the SDK and the per-tool scope challenge.
func TestBodyInspection(t *testing.T) {
	server := newTestServer(t, newAuthority(), func(s *config.RuntimeMCPServerSection) { s.Limits.MaxRequestBytes = 512 })

	for name, tc := range map[string]struct {
		token   string
		body    string
		headers map[string]string
		status  int
	}{
		"duplicate names":     {"good", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`, nil, http.StatusBadRequest},
		"batch":               {"good", `[` + toolCall(supportapi.OperationDiagnostics, `{}`) + `]`, nil, http.StatusBadRequest},
		"oversized":           {"good", toolCall(supportapi.OperationDiagnostics, `{"x":"`+strings.Repeat("a", 600)+`"}`), nil, http.StatusRequestEntityTooLarge},
		"method mismatch":     {"good", toolCall(supportapi.OperationDiagnostics, `{}`), map[string]string{headerMCPMethod: "tools/list"}, http.StatusBadRequest},
		"name mismatch":       {"good", toolCall(supportapi.OperationDiagnostics, `{}`), map[string]string{headerMCPName: "bruteforce_history"}, http.StatusBadRequest},
		"tool scope":          {"history-only", toolCall(supportapi.OperationDiagnostics, `{"schema_version":"1"}`), nil, http.StatusForbidden},
		"method case variant": {"history-only", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"operational_diagnostics","arguments":{"schema_version":"1"}}}`, nil, http.StatusBadRequest},
		"name case variant":   {"history-only", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bruteforce_history","Name":"operational_diagnostics"}}`, nil, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request := proxied(http.MethodPost, "/mcp", tc.body, tc.token)
			for key, value := range tc.headers {
				request.Header.Set(key, value)
			}

			recorder := serve(server, request)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			if tc.status == http.StatusForbidden && !strings.Contains(recorder.Header().Get("WWW-Authenticate"),
				`error="insufficient_scope", scope="nauthilus:operations_read"`) {
				t.Fatalf("WWW-Authenticate = %q", recorder.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

// proxyTransport adds the bearer token and the trusted proxy headers to every SDK client request.
type proxyTransport struct {
	token string
}

// RoundTrip forwards the request as the trusted proxy would.
func (p proxyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Host = testHost
	clone.Header.Set("Authorization", "Bearer "+p.token)
	clone.Header.Set(headerForwardedProto, "https")
	clone.Header.Set(headerForwardedFor, "203.0.113.50")

	return http.DefaultTransport.RoundTrip(clone)
}

// connect runs an SDK client against the endpoint with the given protocol version.
func connect(t *testing.T, server *Server, token string, version string) *mcp.ClientSession {
	t.Helper()

	listener := httptest.NewServer(server.Handler())
	t.Cleanup(listener.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "nauthilus-test", Version: "1"}, nil)

	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: listener.URL + "/mcp",
		HTTPClient: &http.Client{Transport: proxyTransport{token: token}}}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("Connect(%s) = %v", version, err)
	}

	t.Cleanup(func() { _ = session.Close() })

	return session
}

// TestProtocolErasListAndCallTools pins that the stateless 2026-07-28 protocol and the handshake era both list every
// read-only tool and run a call through the shared operation table.
func TestProtocolErasListAndCallTools(t *testing.T) {
	server := newTestServer(t, newAuthority(), func(s *config.RuntimeMCPServerSection) {
		s.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	})

	for _, version := range []string{"2026-07-28", "2025-11-25", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			session := connect(t, server, "good", version)

			assertReadOnlyTools(t, session)
			assertToolCalls(t, session)
		})
	}
}

// assertReadOnlyTools checks that every operation is listed as a read-only, closed-world tool with the untrusted-data
// notice.
func assertReadOnlyTools(t *testing.T, session *mcp.ClientSession) {
	t.Helper()

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	names := make([]string, 0, len(tools.Tools))

	for _, tool := range tools.Tools {
		names = append(names, tool.Name)

		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || *tool.Annotations.DestructiveHint ||
			!strings.Contains(tool.Description, "untrusted data") {
			t.Fatalf("tool %s annotations = %+v", tool.Name, tool.Annotations)
		}
	}

	want := []string{supportapi.OperationAttemptSearch, supportapi.OperationAttemptDetail,
		supportapi.OperationBanHistory, supportapi.OperationDiagnostics}
	slices.Sort(want)

	if !slices.Equal(names, want) {
		t.Fatalf("tools = %v", names)
	}
}

// assertToolCalls checks one processed call and one service error through the shared operation table.
func assertToolCalls(t *testing.T, session *mcp.ClientSession) {
	t.Helper()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: supportapi.OperationDiagnostics,
		Arguments: map[string]any{"schema_version": "1"}})
	if err != nil || result.IsError {
		t.Fatalf("CallTool = %+v, %v", result, err)
	}

	history, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: supportapi.OperationAttemptSearch,
		Arguments: map[string]any{"schema_version": "1"}})
	if err != nil || !history.IsError || !strings.Contains(history.Content[0].(*mcp.TextContent).Text, "HISTORY_NOT_CONFIGURED") {
		t.Fatalf("history without source = %+v, %v", history, err)
	}
}

// TestResponseCap pins that a result above max_response_bytes is replaced by RESPONSE_TOO_LARGE.
func TestResponseCap(t *testing.T) {
	server := newTestServer(t, newAuthority(), func(s *config.RuntimeMCPServerSection) {
		s.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
		s.Limits.MaxResponseBytes = 64
	})

	result, err := connect(t, server, "good", "2025-06-18").CallTool(context.Background(),
		&mcp.CallToolParams{Name: supportapi.OperationDiagnostics, Arguments: map[string]any{"schema_version": "1"}})
	if err != nil || !result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "RESPONSE_TOO_LARGE") {
		t.Fatalf("CallTool = %+v, %v", result, err)
	}
}

// TestNewRequiresHostedResource pins the constructor boundary.
func TestNewRequiresHostedResource(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("empty deps must be rejected")
	}

	_, err := New(Deps{Settings: &config.RuntimeMCPServerSection{HostedResource: "missing"}, Tokens: newAuthority()})
	if err == nil {
		t.Fatal("an unknown hosted resource must be rejected")
	}
}
