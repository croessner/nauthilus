package pluginruntime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

const (
	testRuntimeHookName      = "webhook"
	testRuntimeHookBody      = "payload"
	testRuntimeHookClientID  = "client-app"
	testRuntimeHookHeaderOK  = "ok"
	testRuntimeHookPath      = "/" + testRuntimeHookName
	testRuntimeHookQualified = testRuntimeModuleName + "." + testRuntimeHookName
	testRuntimeRequestID     = "request-1"
	testRuntimeHookAPIKey    = "X-Api-Key"
	testRuntimeHookRepeat    = "X-Repeat"
	testRuntimeHookSingle    = "X-Single"
	testRuntimeHookSingleOK  = "single-header-value"
)

func TestRunner_HooksReturnsRegisteredDescriptors(t *testing.T) {
	runner := newTestRunner(t, &runtimePlugin{}, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterHook(&runtimeHook{name: testRuntimeHookName})
	})

	hooks := runner.Hooks()
	if len(hooks) != 1 {
		t.Fatalf("Hooks() length = %d, want 1", len(hooks))
	}

	got := hooks[0]
	if got.QualifiedName != testRuntimeHookQualified {
		t.Fatalf("QualifiedName = %q, want %q", got.QualifiedName, testRuntimeHookQualified)
	}

	if got.Kind != pluginregistry.ComponentKindHook {
		t.Fatalf("Kind = %q, want hook", got.Kind)
	}

	if got.HookDescriptor.Path != testRuntimeHookPath || got.HookDescriptor.Method != http.MethodPost {
		t.Fatalf("HookDescriptor = %#v, want POST /webhook", got.HookDescriptor)
	}
}

func TestRunner_ServeHookReturnsResponseAndObservation(t *testing.T) {
	observer := &recordingObserver{}
	hook := &runtimeHook{
		name: testRuntimeHookName,
		response: pluginapi.HookResponse{
			StatusCode: http.StatusCreated,
			Headers:    map[string][]string{"X-Plugin": {testRuntimeHookHeaderOK}},
			Body:       []byte("created"),
		},
	}
	runner := newTestRunner(
		t,
		&runtimePlugin{},
		func(registrar pluginapi.Registrar) error {
			return registrar.RegisterHook(hook)
		},
		WithObserver(observer),
	)

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	result, err := runner.ServeHook(context.Background(), testRuntimeHookQualified, pluginapi.HookRequest{
		Method: http.MethodPost,
		Path:   testRuntimeHookPath,
		Body:   []byte(testRuntimeHookBody),
	})
	if err != nil {
		t.Fatalf("ServeHook() error = %v", err)
	}

	if result.StatusCode != http.StatusCreated || string(result.Body) != "created" {
		t.Fatalf("ServeHook() result = %#v, want created response", result)
	}

	if string(hook.request.Body) != testRuntimeHookBody {
		t.Fatalf("hook request body = %q, want %s", hook.request.Body, testRuntimeHookBody)
	}

	if !observer.sawCall(testRuntimeHookName, string(pluginregistry.ComponentKindHook), "Serve") {
		t.Fatalf("observer records = %#v, want hook Serve call", observer.records)
	}
}

func TestRunner_ServeHookPanicBoundaryIsSecretSafe(t *testing.T) {
	observer := &recordingObserver{}
	runner := newTestRunner(
		t,
		&runtimePlugin{},
		func(registrar pluginapi.Registrar) error {
			return registrar.RegisterHook(&runtimeHook{
				name:         testRuntimeHookName,
				panicMessage: "panic contains hook-secret",
			})
		},
		WithObserver(observer),
	)

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	_, err := runner.ServeHook(context.Background(), testRuntimeHookQualified, pluginapi.HookRequest{})
	if !errors.Is(err, ErrPluginPanic) {
		t.Fatalf("ServeHook() error = %v, want ErrPluginPanic", err)
	}

	if strings.Contains(err.Error(), "hook-secret") {
		t.Fatalf("ServeHook() panic error leaked secret: %v", err)
	}

	if !observer.sawPanic(testRuntimeHookName, "Serve") {
		t.Fatalf("observer records = %#v, want panic for hook Serve", observer.records)
	}
}

func TestNewHookRequestFromHTTPRequestRedactsAndCopiesValues(t *testing.T) {
	req := newHookRequestSnapshotTestHTTPRequest()
	body := []byte(testRuntimeHookBody)
	request := NewHookRequestFromHTTPRequest(req, body, hookRequestSnapshotTestMetadata(), WithSnapshotSecretHeaders("X-Secret-Header"))

	assertHookRequestSnapshot(t, request)
	assertHookRequestImmutableCopies(t, request, req, body)
	assertHookRequestCallerMetadata(t, request)
}

// newHookRequestSnapshotTestHTTPRequest builds the source HTTP request for hook snapshot tests.
func newHookRequestSnapshotTestHTTPRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "https://nauthilus.example.test/api/v1/custom/webhook?tag=a&tag=b", strings.NewReader("ignored"))
	req.Header.Set(requestHeaderAuthorization, "Bearer secret")
	req.Header.Set(requestHeaderCookie, "session=secret")
	req.Header.Set("X-Request-ID", testRuntimeRequestID)
	req.Header.Set("X-Secret-Header", "secret")
	req.RemoteAddr = "192.0.2.10:34567"

	return req
}

// hookRequestSnapshotTestMetadata returns caller metadata for hook snapshot tests.
func hookRequestSnapshotTestMetadata() HookRequestMetadata {
	return HookRequestMetadata{
		Session:                  "guid-test",
		ClientIP:                 "203.0.113.5",
		ClientPort:               "12345",
		ClientNet:                requestSnapshotClientNet,
		ClientHost:               requestSnapshotClientHost,
		ClientID:                 requestSnapshotHookClientID,
		LocalIP:                  requestSnapshotLocalIP,
		LocalPort:                requestSnapshotLocalPort,
		OIDCCID:                  testRuntimeHookClientID,
		Username:                 "caller",
		AccountField:             backendTestMailAttr,
		UniqueUserID:             requestSnapshotHookUniqueUserID,
		DisplayName:              requestSnapshotHookDisplayName,
		Authenticated:            true,
		UserFound:                true,
		Authorized:               true,
		NoAuth:                   true,
		Repeating:                true,
		RWP:                      true,
		BruteForceName:           requestSnapshotBruteForceName,
		BruteForceCounter:        3,
		EnvironmentName:          testRuntimeModuleName,
		StatusMessage:            requestSnapshotStatusOK,
		HTTPStatus:               http.StatusAccepted,
		EnvironmentRejected:      true,
		EnvironmentStageExpected: true,
		SubjectStageExpected:     true,
		AuthLoginAttempt:         5,
		IDP: pluginapi.IDPInfo{
			GrantType:               requestSnapshotGrantTypeAuthCode,
			ClientID:                testRuntimeHookClientID,
			ClientName:              requestSnapshotOIDCClientName,
			RedirectURI:             "https://app.example.test/callback",
			RequestedScopes:         []string{requestSnapshotScopeOpenID, requestSnapshotScopeProfile},
			UserGroups:              []string{"admins"},
			AllowedClientScopes:     []string{requestSnapshotScopeOpenID, requestSnapshotScopeProfile, "email"},
			AllowedClientGrantTypes: []string{requestSnapshotGrantTypeAuthCode, "refresh_token"},
			MFACompleted:            true,
			MFAMethod:               "totp",
		},
	}
}

// assertHookRequestImmutableCopies verifies body, header, and query clone boundaries.
func assertHookRequestImmutableCopies(t *testing.T, request pluginapi.HookRequest, req *http.Request, body []byte) {
	t.Helper()

	body[0] = 'X'

	req.Header.Set("X-Request-ID", "changed")
	req.URL.RawQuery = "tag=changed"

	if string(request.Body) != testRuntimeHookBody {
		t.Fatalf("body = %q, want immutable payload copy", request.Body)
	}

	if request.Headers["X-Request-Id"][0] != testRuntimeRequestID {
		t.Fatalf("header changed through source mutation: %#v", request.Headers)
	}

	if request.Query["tag"][0] != "a" {
		t.Fatalf("query changed through source mutation: %#v", request.Query)
	}
}

// assertHookRequestCallerMetadata verifies caller, runtime, diagnostics, and IDP metadata.
func assertHookRequestCallerMetadata(t *testing.T, request pluginapi.HookRequest) {
	t.Helper()

	if !request.Snapshot.Runtime.Authenticated || request.Snapshot.OIDCCID != testRuntimeHookClientID {
		t.Fatalf("snapshot caller metadata = %#v, want authenticated client-app", request.Snapshot)
	}

	assertHookRequestTransportMetadata(t, request)
	assertHookRequestIdentityMetadata(t, request)
	assertHookRequestRuntimeFlags(t, request)
	assertHookRequestDiagnostics(t, request)
	assertHookRequestIDPMetadata(t, request)
}

// assertHookRequestTransportMetadata verifies copied transport and attempt metadata.
func assertHookRequestTransportMetadata(t *testing.T, request pluginapi.HookRequest) {
	t.Helper()

	if request.Snapshot.ClientNet != requestSnapshotClientNet ||
		request.Snapshot.ClientID != requestSnapshotHookClientID ||
		request.Snapshot.LocalIP != requestSnapshotLocalIP ||
		request.Snapshot.LocalPort != requestSnapshotLocalPort ||
		request.Snapshot.AuthLoginAttempt != 5 {
		t.Fatalf("snapshot transport/attempt metadata = %#v, want hook parity values", request.Snapshot)
	}
}

// assertHookRequestIdentityMetadata verifies copied identity metadata.
func assertHookRequestIdentityMetadata(t *testing.T, request pluginapi.HookRequest) {
	t.Helper()

	if request.Snapshot.AccountField != backendTestMailAttr ||
		request.Snapshot.UniqueUserID != requestSnapshotHookUniqueUserID ||
		request.Snapshot.DisplayName != requestSnapshotHookDisplayName {
		t.Fatalf("snapshot identity metadata = %#v, want hook identity values", request.Snapshot)
	}
}

// assertHookRequestRuntimeFlags verifies copied runtime flags.
func assertHookRequestRuntimeFlags(t *testing.T, request pluginapi.HookRequest) {
	t.Helper()

	if !request.Snapshot.Runtime.NoAuth ||
		!request.Snapshot.Runtime.UserFound ||
		!request.Snapshot.Runtime.Authorized ||
		!request.Snapshot.Runtime.EnvironmentRejected ||
		!request.Snapshot.Runtime.EnvironmentStageExpected ||
		!request.Snapshot.Runtime.SubjectStageExpected {
		t.Fatalf("snapshot runtime flags = %#v, want hook parity flags", request.Snapshot.Runtime)
	}
}

// assertHookRequestDiagnostics verifies copied diagnostic metadata.
func assertHookRequestDiagnostics(t *testing.T, request pluginapi.HookRequest) {
	t.Helper()

	if request.Snapshot.Diagnostics.BruteForceName != requestSnapshotBruteForceName ||
		request.Snapshot.Diagnostics.BruteForceCounter != 3 ||
		request.Snapshot.Diagnostics.StatusMessage != requestSnapshotStatusOK ||
		request.Snapshot.Diagnostics.HTTPStatus != http.StatusAccepted {
		t.Fatalf("snapshot diagnostics = %#v, want hook diagnostics", request.Snapshot.Diagnostics)
	}
}

// assertHookRequestIDPMetadata verifies copied IDP metadata.
func assertHookRequestIDPMetadata(t *testing.T, request pluginapi.HookRequest) {
	t.Helper()

	if request.Snapshot.IDP.ClientName != requestSnapshotOIDCClientName ||
		!request.Snapshot.IDP.MFACompleted ||
		len(request.Snapshot.IDP.RequestedScopes) != 2 {
		t.Fatalf("snapshot idp = %#v, want hook idp metadata", request.Snapshot.IDP)
	}
}

func TestNewHookRequestFromHTTPRequestMapsLuaHookHelperInputs(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   []byte
	}{
		{name: "get", method: http.MethodGet},
		{name: "head", method: http.MethodHead, body: []byte("head-input")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://nauthilus.example.test/api/v1/custom/textmap?tag=a&tag=b&empty=", strings.NewReader("ignored"))
			req.Header.Add(testRuntimeHookRepeat, "first")
			req.Header.Add(testRuntimeHookRepeat, "second")
			req.Header.Set(testRuntimeHookSingle, testRuntimeHookSingleOK)
			req.Header.Set(requestHeaderAuthorization, "Bearer secret")
			req.Header.Set(requestHeaderCookie, "session=secret")
			req.Header.Set(testRuntimeHookAPIKey, "secret")

			requestBody := append([]byte(nil), tt.body...)
			hookRequest := NewHookRequestFromHTTPRequest(req, requestBody, HookRequestMetadata{}, WithSnapshotSecretHeaders(testRuntimeHookAPIKey))

			assertHookHelperInputRequest(t, hookRequest, tt.method, requestBody, tt.body)
		})
	}
}

// assertHookHelperInputRequest verifies Lua-style request helpers on HookRequest.
func assertHookHelperInputRequest(t *testing.T, hookRequest pluginapi.HookRequest, method string, sourceBody []byte, wantBody []byte) {
	t.Helper()

	if hookRequest.Method != method || hookRequest.Path != "/api/v1/custom/textmap" {
		t.Fatalf("method/path = %s %s, want %s /api/v1/custom/textmap", hookRequest.Method, hookRequest.Path, method)
	}

	assertHookHelperQuery(t, hookRequest)
	assertHookHelperHeaders(t, hookRequest)
	assertHookHelperBodyClone(t, hookRequest, sourceBody, wantBody)
}

// assertHookHelperQuery verifies repeated and empty query values.
func assertHookHelperQuery(t *testing.T, hookRequest pluginapi.HookRequest) {
	t.Helper()

	if got := hookRequest.Query["tag"]; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("query tag = %#v, want [a b]", got)
	}

	if got := hookRequest.Query["empty"]; len(got) != 1 || got[0] != "" {
		t.Fatalf("query empty = %#v, want one empty value", got)
	}
}

// assertHookHelperHeaders verifies repeated headers and secret redaction.
func assertHookHelperHeaders(t *testing.T, hookRequest pluginapi.HookRequest) {
	t.Helper()

	if got := hookRequest.Headers[testRuntimeHookRepeat]; len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("%s = %#v, want [first second]", testRuntimeHookRepeat, got)
	}

	if got := hookRequest.Headers[testRuntimeHookSingle]; len(got) != 1 || got[0] != testRuntimeHookSingleOK {
		t.Fatalf("%s = %#v, want [%s]", testRuntimeHookSingle, got, testRuntimeHookSingleOK)
	}

	for _, name := range []string{requestHeaderAuthorization, requestHeaderCookie, testRuntimeHookAPIKey} {
		assertHookHeaderAbsent(t, hookRequest, name)
	}
}

// assertHookHelperBodyClone verifies source body mutations cannot reach plugins.
func assertHookHelperBodyClone(t *testing.T, hookRequest pluginapi.HookRequest, sourceBody []byte, wantBody []byte) {
	t.Helper()

	if len(sourceBody) == 0 {
		return
	}

	sourceBody[0] = 'X'

	if string(hookRequest.Body) != string(wantBody) {
		t.Fatalf("body = %q, want immutable clone %q", hookRequest.Body, wantBody)
	}
}

// assertHookRequestSnapshot verifies redaction and stable copies in hook requests.
func assertHookRequestSnapshot(t *testing.T, request pluginapi.HookRequest) {
	t.Helper()

	if request.Method != http.MethodPost || request.Path != "/api/v1/custom/webhook" {
		t.Fatalf("method/path = %s %s, want POST /api/v1/custom/webhook", request.Method, request.Path)
	}

	if got := request.Query["tag"]; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("query tag = %#v, want a,b", got)
	}

	assertHookHeaderAbsent(t, request, requestHeaderAuthorization)
	assertHookHeaderAbsent(t, request, requestHeaderCookie)
	assertHookHeaderAbsent(t, request, "X-Secret-Header")

	if got := request.Headers["X-Request-Id"]; len(got) != 1 || got[0] != testRuntimeRequestID {
		t.Fatalf("X-Request-Id = %#v, want request-1", got)
	}
}

// assertHookHeaderAbsent verifies a redacted header did not reach the plugin.
func assertHookHeaderAbsent(t *testing.T, request pluginapi.HookRequest, name string) {
	t.Helper()

	if _, ok := request.Headers[name]; ok {
		t.Fatalf("%s header reached hook request", name)
	}
}

type runtimeHook struct {
	response     pluginapi.HookResponse
	request      pluginapi.HookRequest
	panicMessage string
	name         string
}

// Descriptor returns the test hook metadata.
func (h runtimeHook) Descriptor() pluginapi.HookDescriptor {
	name := h.name
	if name == "" {
		name = testRuntimeHookName
	}

	return pluginapi.HookDescriptor{
		Timeout:      time.Second,
		Name:         name,
		Method:       http.MethodPost,
		Path:         "/" + name,
		Scope:        pluginapi.HookScopePublic,
		Auth:         pluginapi.HookAuthNone,
		MaxBodyBytes: 1024,
	}
}

// Serve records the test request and returns the configured response.
func (h *runtimeHook) Serve(_ context.Context, request pluginapi.HookRequest) (pluginapi.HookResponse, error) {
	if h.panicMessage != "" {
		panic(h.panicMessage)
	}

	h.request = request

	return h.response, nil
}
