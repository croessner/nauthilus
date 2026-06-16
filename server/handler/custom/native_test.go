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

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"

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

func TestNativeHookTokenAuthAllowsMatchingScope(t *testing.T) {
	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusOK}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		validator: &nativeHookTokenValidator{claims: jwt.MapClaims{"sub": nativeHookTestClientID, "client_id": nativeHookTestClientID, nativeHookClaimScope: definitions.ScopeAuthenticate}},
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
	assertNativeHookTokenRejectedBeforePlugin(t, jwt.MapClaims{nativeHookClaimScope: definitions.ScopeAuthenticate}, "", http.StatusUnauthorized)
}

func TestNativeHookTokenAuthRejectsMissingScopeBeforePlugin(t *testing.T) {
	assertNativeHookTokenRejectedBeforePlugin(t, jwt.MapClaims{nativeHookClaimScope: definitions.ScopeSecurity}, "Bearer token", http.StatusForbidden)
}

func TestNativeHookBodyLimitRejectsBeforePlugin(t *testing.T) {
	runner := &nativeHookTestRunner{response: pluginapi.HookResponse{StatusCode: http.StatusOK}}
	router := newNativeHookTestRouter(t, nativeHookTestConfig{
		hook: nativeHookTestBinding(runner, pluginapi.HookDescriptor{
			Name:         nativeHookTestName,
			Method:       http.MethodPost,
			Path:         nativeHookTestPath,
			Scope:        pluginapi.HookScopePublic,
			Auth:         pluginapi.HookAuthNone,
			MaxBodyBytes: 3,
		}),
	})

	rec := performNativeHookRequest(router, http.MethodPost, nativeHookTestAPIPath, "toolarge", "")

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s, want 413", rec.Code, rec.Body.String())
	}

	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want zero before body limit success", runner.calls)
	}
}

func TestNativeHookRejectsHopByHopResponseHeader(t *testing.T) {
	assertNativeHookRejectsResponseHeader(t, nativeHookHeaderConnection, "close")
}

func TestNativeHookRejectsHostOwnedResponseHeader(t *testing.T) {
	assertNativeHookRejectsResponseHeader(t, nativeHookHeaderCSP, "default-src 'none'")
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

type nativeHookTestConfig struct {
	validator        *nativeHookTokenValidator
	hook             NativeHook
	withAliasNoRoute bool
}

func newNativeHookTestRouter(t *testing.T, cfg nativeHookTestConfig) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)

	file := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}}
	provider := configfx.NewProviderWithSnapshot(file)
	router := gin.New()
	handler := New(
		provider,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
		cfg.validator,
		WithNativeHooks([]NativeHook{cfg.hook}),
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

func performNativeHookRequest(router http.Handler, method string, path string, body string, authorization string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, stringsReader(body))
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("User-Agent", "native-hook-test")

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
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
