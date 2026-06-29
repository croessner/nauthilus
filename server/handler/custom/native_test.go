package custom

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	nativeHookTestPath      = "/native"
	nativeHookTestAPIPath   = "/api/v1/custom/native"
	nativeHookTestQualified = "module.native"
	nativeHookTestName      = "native"
	nativeHookTestOK        = "ok"
	nativeHookTestClientID  = "client-a"
	nativeHookClaimScope    = "scope"
	nativeHookTestXPlugin   = "X-Plugin"
	nativeHookTestFirst     = "first"
	nativeHookTestSecond    = "second"
	nativeHookTestMethodGet = "get"
	nativeHookTestSecret    = "X-Secret-Password"
	nativeHookTestAlias     = "/native-alias"
	nativeHookTestHead      = "head"
	nativeHookTestRepeat    = "repeat"
)

func TestNativeHookRouteRegistrationAndSuccessResponse(t *testing.T) {
	runner := &nativeHookTestRunner{
		response: pluginapi.HookResponse{
			StatusCode: http.StatusCreated,
			Headers:    map[string][]string{nativeHookTestXPlugin: {nativeHookTestOK}},
			Body:       []byte("created"),
		},
	}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodPost,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodPost, nativeHookTestAPIPath, "payload", "")

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s, want 201", rec.Code, rec.Body.String())
	}

	if rec.Body.String() != "created" {
		t.Fatalf("body = %q, want created", rec.Body.String())
	}

	if got := rec.Header().Get(nativeHookTestXPlugin); got != nativeHookTestOK {
		t.Fatalf("X-Plugin = %q, want ok", got)
	}

	if runner.calls != 1 || runner.qualifiedName != nativeHookTestQualified {
		t.Fatalf("runner calls = %d qualified=%q, want one %s", runner.calls, runner.qualifiedName, nativeHookTestQualified)
	}

	if runner.request.Path != nativeHookTestAPIPath || string(runner.request.Body) != "payload" {
		t.Fatalf("request = %#v, want API-level request with body", runner.request)
	}
}

func TestNativeHookGETAndHEADResponsesAreDeterministic(t *testing.T) {
	getRunner := &nativeHookTestRunner{
		response: pluginapi.HookResponse{
			StatusCode: http.StatusOK,
			Headers: map[string][]string{
				nativeHookTestXPlugin: {nativeHookTestMethodGet, nativeHookTestRepeat},
			},
			Body: []byte("textmap\n"),
		},
	}
	headRunner := &nativeHookTestRunner{
		response: pluginapi.HookResponse{
			StatusCode: http.StatusOK,
			Headers: map[string][]string{
				nativeHookTestXPlugin: {nativeHookTestHead},
			},
			Body: []byte("head body must not be written"),
		},
	}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		hooks: []NativeHook{
			nativeHookTestBinding(getRunner, pluginapi.HookDescriptor{
				Name:         "native_get",
				Method:       http.MethodGet,
				Path:         nativeHookTestPath,
				Scope:        pluginapi.HookScopePublic,
				Auth:         pluginapi.HookAuthNone,
				MaxBodyBytes: 32,
			}),
			nativeHookTestBinding(headRunner, pluginapi.HookDescriptor{
				Name:         "native_head",
				Method:       http.MethodHead,
				Path:         nativeHookTestPath,
				Scope:        pluginapi.HookScopePublic,
				Auth:         pluginapi.HookAuthNone,
				MaxBodyBytes: 32,
			}),
		},
	})

	getRec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath+"?tag=a&tag=b", "", "")
	assertNativeHookGETTextmapResponse(t, getRec, getRunner.request)

	headRec := performNativeHookRequest(router, http.MethodHead, nativeHookTestAPIPath, "", "")
	assertNativeHookHEADTextmapResponse(t, headRec, headRunner.request)
}

// assertNativeHookGETTextmapResponse verifies GET body, headers, and query mapping.
func assertNativeHookGETTextmapResponse(t *testing.T, rec *httptest.ResponseRecorder, request pluginapi.HookRequest) {
	t.Helper()

	if rec.Code != http.StatusOK || rec.Body.String() != "textmap\n" {
		t.Fatalf("GET response = %d %q, want 200 textmap body", rec.Code, rec.Body.String())
	}

	if values := rec.Header().Values(nativeHookTestXPlugin); len(values) != 2 || values[0] != nativeHookTestMethodGet || values[1] != nativeHookTestRepeat {
		t.Fatalf("GET X-Plugin values = %#v, want [get repeat]", values)
	}

	if got := request.Query["tag"]; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("GET query tag = %#v, want [a b]", got)
	}
}

// assertNativeHookHEADTextmapResponse verifies HEAD headers without body leakage.
func assertNativeHookHEADTextmapResponse(t *testing.T, rec *httptest.ResponseRecorder, request pluginapi.HookRequest) {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d body=%q, want 200", rec.Code, rec.Body.String())
	}

	if got := rec.Body.String(); got != "" {
		t.Fatalf("HEAD body = %q, want empty body", got)
	}

	if got := rec.Header().Get(nativeHookTestXPlugin); got != nativeHookTestHead {
		t.Fatalf("HEAD X-Plugin = %q, want head", got)
	}

	if request.Method != http.MethodHead || request.Path != nativeHookTestAPIPath {
		t.Fatalf("HEAD request metadata = %s %s, want HEAD %s", request.Method, request.Path, nativeHookTestAPIPath)
	}
}

func TestNativeHookUnsupportedMethodDoesNotInvokePlugin(t *testing.T) {
	runner, router := newNativeHookTestRouterForMethod(t, http.MethodGet, 32)
	rec := performNativeHookRequest(router, http.MethodPost, nativeHookTestAPIPath, "payload", "")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s, want 404 for unsupported method", rec.Code, rec.Body.String())
	}

	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want zero for unsupported method", runner.calls)
	}
}

func TestNativeHookLowercaseMethodDescriptorDispatchesAlias(t *testing.T) {
	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusAccepted}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		withAliasNoRoute: true,
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       nativeHookTestMethodGet,
			Path:         nativeHookTestPath,
			Alias:        nativeHookTestAlias,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAlias, "", "")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s, want 202", rec.Code, rec.Body.String())
	}

	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want one", runner.calls)
	}
}

func TestNativeHookTokenAuthAllowsMatchingScope(t *testing.T) {
	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusOK}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		validator: &nativeHookTokenValidator{claims: nativeHookAccessClaims(definitions.ScopeAuthenticate)},
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopeInternal,
			Auth:         pluginapi.HookAuthToken,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath, "", "Bearer token")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}

	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want one", runner.calls)
	}

	if !runner.request.Snapshot.Runtime.Authenticated || runner.request.Snapshot.OIDCCID != nativeHookTestClientID {
		t.Fatalf("snapshot caller metadata = %#v, want authenticated client-a", runner.request.Snapshot)
	}
}

func TestNativeHookTokenAuthRejectsMissingTokenBeforePlugin(t *testing.T) {
	assertNativeHookTokenRejectedBeforePlugin(t, nativeHookAccessClaims(definitions.ScopeAuthenticate), "", http.StatusUnauthorized)
}

func TestNativeHookTokenAuthRejectsMissingScopeBeforePlugin(t *testing.T) {
	assertNativeHookTokenRejectedBeforePlugin(t, nativeHookAccessClaims(definitions.ScopeSecurity), "Bearer token", http.StatusForbidden)
}

func TestNativeHookAdminAuthRejectsInternalScopeTokenBeforePlugin(t *testing.T) {
	assertNativeHookAdminAuthStatus(t, definitions.ScopeAuthenticate, http.StatusForbidden, 0)
}

func TestNativeHookAdminAuthAllowsAdminScopeToken(t *testing.T) {
	assertNativeHookAdminAuthStatus(t, definitions.ScopeAdmin, http.StatusOK, 1)
}

func TestNativeHookBodyLimitRejectsBeforePlugin(t *testing.T) {
	runner, router := newNativeHookTestRouterForMethod(t, http.MethodPost, 3)
	rec := performNativeHookRequest(router, http.MethodPost, nativeHookTestAPIPath, "toolarge", "")

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s, want 413", rec.Code, rec.Body.String())
	}

	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want zero before body limit success", runner.calls)
	}
}

// assertNativeHookAdminAuthStatus verifies admin-auth descriptor behavior.
func assertNativeHookAdminAuthStatus(t *testing.T, scope string, wantStatus int, wantCalls int) {
	t.Helper()

	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusOK}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		validator: &nativeHookTokenValidator{claims: nativeHookAccessClaims(scope)},
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopeInternal,
			Auth:         pluginapi.HookAuthAdmin,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath, "", "Bearer token")
	if rec.Code != wantStatus {
		t.Fatalf("status = %d body=%s, want %d", rec.Code, rec.Body.String(), wantStatus)
	}

	if runner.calls != wantCalls {
		t.Fatalf("runner calls = %d, want %d", runner.calls, wantCalls)
	}
}

// nativeHookAccessClaims returns valid backchannel access-token claims for hook tests.
func nativeHookAccessClaims(scope string) jwt.MapClaims {
	return jwt.MapClaims{
		"aud":                      definitions.AudienceBackchannelAPI,
		"client_id":                nativeHookTestClientID,
		"sub":                      nativeHookTestClientID,
		nativeHookClaimScope:       scope,
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
}

func TestNativeHookRejectsHopByHopResponseHeader(t *testing.T) {
	assertNativeHookRejectsResponseHeader(t, nativeHookHeaderConnection, "close")
}

func TestNativeHookRejectsHostOwnedResponseHeader(t *testing.T) {
	assertNativeHookRejectsResponseHeader(t, nativeHookHeaderCSP, "default-src 'none'")
}

func TestNativeHookRejectsSecretBearingResponseHeaders(t *testing.T) {
	for _, header := range []string{"Authorization", "Set-Cookie", nativeHookTestSecret} {
		t.Run(header, func(t *testing.T) {
			assertNativeHookRejectsResponseHeader(t, header, "secret")
		})
	}
}

// assertNativeHookTokenRejectedBeforePlugin verifies auth/scope failures do not invoke plugin code.
func assertNativeHookTokenRejectedBeforePlugin(t *testing.T, claims jwt.MapClaims, token string, wantStatus int) {
	t.Helper()

	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusOK}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		validator: &nativeHookTokenValidator{claims: claims},
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopeInternal,
			Auth:         pluginapi.HookAuthToken,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath, "", token)
	if rec.Code != wantStatus {
		t.Fatalf("status = %d body=%s, want %d", rec.Code, rec.Body.String(), wantStatus)
	}

	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want zero before auth success", runner.calls)
	}
}

// assertNativeHookRejectsResponseHeader verifies unsafe plugin response headers are blocked.
func assertNativeHookRejectsResponseHeader(t *testing.T, header string, value string) {
	t.Helper()

	runner := &nativeHookTestRunner{
		response: pluginapi.HookResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{header: {value}},
			Body:       []byte("unsafe"),
		},
	}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath, "", "")

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s, want 502", rec.Code, rec.Body.String())
	}

	if rec.Header().Get(header) != "" {
		t.Fatalf("unsafe response header %s was written: %#v", header, rec.Header())
	}
}

func TestNativeHookRejectsInvalidResponseHeaders(t *testing.T) {
	tests := []struct {
		headers map[string][]string
		name    string
	}{
		{
			name: "invalid name",
			headers: map[string][]string{
				"Bad\nName": {"value"},
			},
		},
		{
			name: "invalid value",
			headers: map[string][]string{
				nativeHookTestXPlugin: {"bad\r\nvalue"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &nativeHookTestRunner{
				response: pluginapi.HookResponse{
					StatusCode: http.StatusOK,
					Headers:    tt.headers,
					Body:       []byte("unsafe"),
				},
			}
			router := newNativeHookTestRouter(t, nativeHookTestConfig{
				hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
					Name:         nativeHookTestName,
					Method:       http.MethodGet,
					Path:         nativeHookTestPath,
					Scope:        pluginapi.HookScopePublic,
					Auth:         pluginapi.HookAuthNone,
					MaxBodyBytes: 32,
				}),
			})

			rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath, "", "")

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d body=%s, want 502", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestNativeHookTimeoutMapsToGatewayTimeout(t *testing.T) {
	runner := &nativeHookTestRunner{waitForCancel: true}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			Timeout:      time.Nanosecond,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath, "", "")

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d body=%s, want 504", rec.Code, rec.Body.String())
	}
}

func TestNativeHookPluginErrorIsSecretSafe(t *testing.T) {
	runner := &nativeHookTestRunner{err: errors.New("database failed with secret-token")}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, nativeHookTestAPIPath, "", "")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s, want 500", rec.Code, rec.Body.String())
	}

	if bytes.Contains(rec.Body.Bytes(), []byte("secret-token")) {
		t.Fatalf("response leaked plugin error: %s", rec.Body.String())
	}
}

func TestNativeHookAliasDispatchesThroughCustomHandler(t *testing.T) {
	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusAccepted}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		withAliasNoRoute: true,
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Alias:        "/native-alias",
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodGet, "/native-alias", "", "")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s, want 202", rec.Code, rec.Body.String())
	}

	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want one", runner.calls)
	}
}

func TestNativeHookIndexOmitsDuplicateCanonicalBindings(t *testing.T) {
	index := newNativeHookIndex([]NativeHook{
		nativeHookTestBinding(&nativeHookTestRunner{}, pluginapi.HookDescriptor{
			Name:         nativeHookTestFirst,
			Method:       http.MethodGet,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
		nativeHookTestBinding(&nativeHookTestRunner{}, pluginapi.HookDescriptor{
			Name:         nativeHookTestSecond,
			Method:       nativeHookTestMethodGet,
			Path:         "native",
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
	})

	if hook, found := index.lookup(nativeHookTestPath, http.MethodGet); found {
		t.Fatalf("duplicate canonical hook stayed routable as %#v", hook.Descriptor)
	}
}

func TestNativeHookIndexOmitsDuplicateAliasBindings(t *testing.T) {
	index := newNativeHookIndex([]NativeHook{
		nativeHookTestBinding(&nativeHookTestRunner{}, pluginapi.HookDescriptor{
			Name:         nativeHookTestFirst,
			Method:       http.MethodGet,
			Path:         "/native-first",
			Alias:        "/native-alias",
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
		nativeHookTestBinding(&nativeHookTestRunner{}, pluginapi.HookDescriptor{
			Name:         nativeHookTestSecond,
			Method:       nativeHookTestMethodGet,
			Path:         "/native-second",
			Alias:        "native-alias",
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 32,
		}),
	})

	if _, found := index.lookup("/native-first", http.MethodGet); !found {
		t.Fatal("first canonical hook was unexpectedly removed")
	}

	if _, found := index.lookup("/native-second", http.MethodGet); !found {
		t.Fatal("second canonical hook was unexpectedly removed")
	}

	if _, found := index.aliasMap()[nativeHookKey("/native-alias", http.MethodGet)]; found {
		t.Fatal("duplicate alias stayed routable")
	}
}

type nativeHookTestConfig struct {
	validator        *nativeHookTokenValidator
	hook             NativeHook
	hooks            []NativeHook
	withAliasNoRoute bool
}

func newNativeHookTestRouter(t *testing.T, cfg nativeHookTestConfig) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)

	file := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}}
	file.Server.DefaultHTTPRequestHeader.Password = nativeHookTestSecret
	provider := configfx.NewProviderWithSnapshot(file)
	router := gin.New()

	hooks := cfg.hooks
	if len(hooks) == 0 && cfg.hook.Runner != nil {
		hooks = []NativeHook{cfg.hook}
	}

	handler := New(
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		cfg.validator,
		WithNativeHooks(hooks),
	)
	handler.Register(router.Group("/api/v1"))

	if cfg.withAliasNoRoute {
		router.NoRoute(func(ctx *gin.Context) {
			if DispatchAlias(ctx) {
				return
			}

			ctx.Status(http.StatusNotFound)
		})
	}

	return router
}

// newNativeHookTestRouterForMethod returns a public hook router for one method.
func newNativeHookTestRouterForMethod(t *testing.T, method string, maxBodyBytes int64) (*nativeHookTestRunner, *gin.Engine) {
	t.Helper()

	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusOK}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       method,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: maxBodyBytes,
		}),
	})

	return runner, router
}

// nativeHookRequestOptions customizes test HTTP requests without duplicating request setup.
type nativeHookRequestOptions struct {
	headers       map[string][]string
	body          string
	authorization string
}

func nativeHookTestBinding(runner *nativeHookTestRunner, descriptor pluginapi.HookDescriptor) NativeHook {
	return NativeHook{
		Descriptor:    descriptor,
		QualifiedName: nativeHookTestQualified,
		ModuleName:    "module",
		ComponentName: nativeHookTestName,
		Runner:        runner,
		BuildRequest:  nativeHookTestRequestBuilder,
	}
}

// performNativeHookRequest executes one native hook request with default test metadata.
func performNativeHookRequest(router http.Handler, method string, path string, body string, authorization string) *httptest.ResponseRecorder {
	return performNativeHookRequestWithOptions(router, method, path, nativeHookRequestOptions{
		body:          body,
		authorization: authorization,
	})
}

// performNativeHookRequestWithOptions executes one native hook request with optional headers.
func performNativeHookRequestWithOptions(router http.Handler, method string, path string, options nativeHookRequestOptions) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, stringsReader(options.body))
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("User-Agent", "native-hook-test")

	for key, values := range options.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	if options.authorization != "" {
		req.Header.Set("Authorization", options.authorization)
	}

	router.ServeHTTP(rec, req)

	return rec
}

func stringsReader(value string) io.Reader {
	if value == "" {
		return http.NoBody
	}

	return bytes.NewBufferString(value)
}

func nativeHookTestRequestBuilder(
	ctx *gin.Context,
	_ config.File,
	_ pluginapi.HookDescriptor,
	caller NativeHookCaller,
	body []byte,
) (pluginapi.HookRequest, error) {
	headers := make(map[string][]string, len(ctx.Request.Header))
	for key, values := range ctx.Request.Header {
		headers[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}

	query := make(map[string][]string, len(ctx.Request.URL.Query()))
	for key, values := range ctx.Request.URL.Query() {
		query[key] = append([]string(nil), values...)
	}

	return pluginapi.HookRequest{
		Snapshot: pluginapi.RequestSnapshot{
			Headers:  headers,
			Method:   ctx.Request.Method,
			OIDCCID:  caller.ClientID,
			Username: caller.Subject,
			Runtime:  pluginapi.RuntimeFlags{Authenticated: caller.Authenticated},
		},
		Headers: headers,
		Query:   query,
		Body:    append([]byte(nil), body...),
		Path:    ctx.Request.URL.Path,
		Method:  ctx.Request.Method,
	}, nil
}

type nativeHookTestRunner struct {
	response      pluginapi.HookResponse
	request       pluginapi.HookRequest
	err           error
	qualifiedName string
	calls         int
	waitForCancel bool
}

func (r *nativeHookTestRunner) ServeHook(ctx context.Context, qualifiedName string, request pluginapi.HookRequest) (pluginapi.HookResponse, error) {
	r.calls++
	r.qualifiedName = qualifiedName
	r.request = request

	if r.waitForCancel {
		<-ctx.Done()

		return pluginapi.HookResponse{}, ctx.Err()
	}

	return r.response, r.err
}

type nativeHookTokenValidator struct {
	claims jwt.MapClaims
	err    error
}

func (v *nativeHookTokenValidator) ValidateToken(context.Context, string) (jwt.MapClaims, error) {
	return v.claims, v.err
}
