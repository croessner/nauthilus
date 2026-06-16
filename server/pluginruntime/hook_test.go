package pluginruntime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/pluginregistry"
)

const (
	testRuntimeHookName      = "webhook"
	testRuntimeHookBody      = "payload"
	testRuntimeHookClientID  = "client-app"
	testRuntimeHookHeaderOK  = "ok"
	testRuntimeHookPath      = "/" + testRuntimeHookName
	testRuntimeHookQualified = testRuntimeModuleName + "." + testRuntimeHookName
	testRuntimeRequestID     = "request-1"
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
	req := httptest.NewRequest(http.MethodPost, "https://nauthilus.example.test/api/v1/custom/webhook?tag=a&tag=b", strings.NewReader("ignored"))
	req.Header.Set(requestHeaderAuthorization, "Bearer secret")
	req.Header.Set(requestHeaderCookie, "session=secret")
	req.Header.Set("X-Request-ID", testRuntimeRequestID)
	req.Header.Set("X-Secret-Header", "secret")
	req.RemoteAddr = "192.0.2.10:34567"

	body := []byte(testRuntimeHookBody)
	request := NewHookRequestFromHTTPRequest(req, body, HookRequestMetadata{
		Session:       "guid-test",
		ClientIP:      "203.0.113.5",
		ClientPort:    "12345",
		ClientHost:    "client.example.test",
		OIDCCID:       testRuntimeHookClientID,
		Username:      "caller",
		Authenticated: true,
	}, WithSnapshotSecretHeaders("X-Secret-Header"))

	assertHookRequestSnapshot(t, request)

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

	if !request.Snapshot.Runtime.Authenticated || request.Snapshot.OIDCCID != testRuntimeHookClientID {
		t.Fatalf("snapshot caller metadata = %#v, want authenticated client-app", request.Snapshot)
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
