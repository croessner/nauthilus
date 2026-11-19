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

package support

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/openapi/requesttest"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// fixtureBase is the instant the newest fixture row is shifted to.
var fixtureBase = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

// testRouter mounts the handler below /api/v1 with a stand-in for the validated backchannel middleware.
func testRouter(t *testing.T, service *supporthistory.Service, claims jwt.MapClaims, basic bool) *gin.Engine {
	t.Helper()

	return testRouterWithDeps(t, &handlerdeps.Deps{SupportHistory: service}, claims, basic)
}

// testRouterWithDeps mounts the handler over the given support services for a Bearer or unrestricted Basic caller.
func testRouterWithDeps(t *testing.T, deps *handlerdeps.Deps, claims jwt.MapClaims, basic bool) *gin.Engine {
	t.Helper()

	return testRouterWithCaller(t, deps, func(ctx *gin.Context) {
		if claims != nil {
			oidcbearer.BindClaims(ctx, claims)
		}

		if basic {
			mdauth.StoreCaller(ctx, mdauth.NewUnrestrictedBasicCaller("management"))
		}
	})
}

// testRouterWithCaller mounts the handler behind a stand-in for the backchannel caller authentication.
func testRouterWithCaller(t *testing.T, deps *handlerdeps.Deps, bindCaller func(ctx *gin.Context)) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	group := engine.Group("/api/v1", func(ctx *gin.Context) {
		bindCaller(ctx)
		ctx.Next()
	})

	New(deps).Register(group)

	return engine
}

// fixtureService builds the service over the shared attempt scenario.
func fixtureService(t *testing.T) *supporthistory.Service {
	t.Helper()

	store, err := historytest.LoadFixture("../../supporthistory/testdata/attempt_scenarios.json", fixtureBase)
	if err != nil {
		t.Fatalf("LoadFixture() error = %v", err)
	}

	service, err := supporthistory.NewService(supporthistory.Options{Attempts: store, Bans: historytest.WithRecordedBan(store, "req-brute"),
		Now: func() time.Time { return fixtureBase.Add(time.Hour) }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// bearer returns validated claims with the given scopes.
func bearer(scopes ...string) jwt.MapClaims {
	return jwt.MapClaims{definitions.ClaimClientID: "support-console", "sub": "support-console",
		"scope": strings.Join(append([]string{definitions.ScopeAuthenticate}, scopes...), " ")}
}

// searchBody returns a valid search body over the fixture window.
func searchBody() string {
	return searchBodyWith("", 5)
}

// searchBodyWith returns a search body over the fixture window with extra members and a page size.
func searchBodyWith(extra string, limit int) string {
	return fmt.Sprintf(`{"schema_version":"1","subject":{"login":"anna@example.test"},`+
		`"filter":{"from":%q,"until":%q},"page":{"limit":%d}%s}`,
		fixtureBase.Add(-2*time.Hour).Format(time.RFC3339), fixtureBase.Add(time.Minute).Format(time.RFC3339), limit, extra)
}

// serve performs one request.
func serve(engine *gin.Engine, target, body string) (*http.Request, *httptest.ResponseRecorder) {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	return request, recorder
}

// errorCode decodes the fixed error envelope.
func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}

	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", recorder.Body.String(), err)
	}

	return body.Error.Code
}

// TestSupportHistoryScopeMatrix pins that only explicit history scopes reach the service; admin and Basic do not.
func TestSupportHistoryScopeMatrix(t *testing.T) {
	service := fixtureService(t)
	target := "/api/v1/support/authentication-attempts/search"

	for name, tc := range map[string]struct {
		claims jwt.MapClaims
		basic  bool
		status int
	}{
		"no credential":      {nil, false, http.StatusForbidden},
		"basic credential":   {nil, true, http.StatusForbidden},
		"base scope only":    {bearer(), false, http.StatusForbidden},
		"admin scope only":   {bearer(definitions.ScopeAdmin, definitions.ScopeSecurity), false, http.StatusForbidden},
		"history read scope": {bearer(definitions.ScopeHistoryRead), false, http.StatusOK},
		"history detail":     {bearer(definitions.ScopeHistoryDetail), false, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			_, recorder := serve(testRouter(t, service, tc.claims, tc.basic), target, searchBody())

			if recorder.Code != tc.status || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status = %d cache = %q body = %s, want %d with no-store", recorder.Code,
					recorder.Header().Get("Cache-Control"), recorder.Body.String(), tc.status)
			}

			if tc.status == http.StatusForbidden && errorCode(t, recorder) != string(supporthistory.CodeForbidden) {
				t.Fatalf("body = %s, want FORBIDDEN", recorder.Body.String())
			}
		})
	}
}

// TestSupportHistoryAuthorizesScopedBasicCredentials verifies that a scoped Basic credential is authorized through
// the support scopes it holds, exactly like a Bearer token carrying them.
func TestSupportHistoryAuthorizesScopedBasicCredentials(t *testing.T) {
	deps := &handlerdeps.Deps{SupportHistory: fixtureService(t)}
	target := "/api/v1/support/authentication-attempts/search"

	for name, tc := range map[string]struct {
		scopes []string
		status int
	}{
		"history read scope":   {[]string{definitions.ScopeHistoryRead}, http.StatusOK},
		"history detail scope": {[]string{definitions.ScopeHistoryDetail}, http.StatusOK},
		"operations scope":     {[]string{definitions.ScopeOperationsRead}, http.StatusForbidden},
		"management scopes":    {[]string{definitions.ScopeAdmin, definitions.ScopeAuthenticate}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			engine := testRouterWithCaller(t, deps, func(ctx *gin.Context) {
				mdauth.StoreCaller(ctx, mdauth.NewScopedCaller(mdauth.CallerMethodBasic, "support-console", tc.scopes))
			})

			_, recorder := serve(engine, target, searchBody())
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}
		})
	}
}

// TestSupportHistoryResponsesMatchTheOpenAPIContract validates real answers of all three operations.
func TestSupportHistoryResponsesMatchTheOpenAPIContract(t *testing.T) {
	validator := requesttest.NewManagementValidator(t)
	engine := testRouter(t, fixtureService(t), bearer(definitions.ScopeHistoryDetail), false)
	around := fixtureBase.Add(-10 * time.Minute).Format(time.RFC3339)

	for name, tc := range map[string]struct {
		target, body string
		status       int
	}{
		"search": {"/api/v1/support/authentication-attempts/search", searchBody(), http.StatusOK},
		"compact search with ban context": {"/api/v1/support/authentication-attempts/search",
			searchBodyWith(`,"include_ban_context":true,"response_mode":"compact"`, 20), http.StatusOK},
		"detailed search with ban context": {"/api/v1/support/authentication-attempts/search",
			searchBodyWith(`,"include_ban_context":true,"response_mode":"detailed"`, 20), http.StatusOK},
		"unknown response mode": {"/api/v1/support/authentication-attempts/search",
			searchBodyWith(`,"response_mode":"verbose"`, 5), http.StatusBadRequest},
		"ban search": {"/api/v1/support/bruteforce-bans/search", fmt.Sprintf(
			`{"schema_version":"1","target":{"network":"198.51.100.0/24"},"filter":{"from":%q,"until":%q}}`,
			fixtureBase.Add(-time.Hour).Format(time.RFC3339), fixtureBase.Format(time.RFC3339)), http.StatusOK},
		"bad window": {"/api/v1/support/authentication-attempts/search", strings.Replace(searchBody(),
			fixtureBase.Add(-2*time.Hour).Format(time.RFC3339), fixtureBase.Add(-40*24*time.Hour).Format(time.RFC3339), 1),
			http.StatusBadRequest},
		"malformed id": {"/api/v1/support/authentication-attempts/detail",
			`{"schema_version":"1","attempt_id":"cookie-value","around":"` + around + `"}`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			request, recorder := serve(engine, tc.target, tc.body)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), tc.status)
			}

			requesttest.AssertRecorderResponse(t, validator, request, recorder, requesttest.ResponseValidation{
				RequiredHeaderValues: map[string]string{"Cache-Control": "no-store"}})
		})
	}
}

// TestSupportHistoryRefusesUnsafeTransportInput pins body-only filters and strict decoding.
func TestSupportHistoryRefusesUnsafeTransportInput(t *testing.T) {
	engine := testRouter(t, fixtureService(t), bearer(definitions.ScopeHistoryRead), false)
	target := "/api/v1/support/authentication-attempts/search"

	for name, tc := range map[string]struct{ target, body string }{
		"query parameters": {target + "?login=anna@example.test", searchBody()},
		"unknown field":    {target, strings.Replace(searchBody(), `"page"`, `"role":"admin","page"`, 1)},
		"trailing data":    {target, searchBody() + `{}`},
		"duplicate member": {target, strings.Replace(searchBody(), `"page"`, `"subject":{"login":"bob@example.test"},"page"`, 1)},
		"oversized body":   {target, `{"schema_version":"1","audit_reference":"` + strings.Repeat("a", 20000) + `"}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, recorder := serve(engine, tc.target, tc.body)
			if recorder.Code != http.StatusBadRequest || errorCode(t, recorder) != string(supporthistory.CodeInvalidRequest) {
				t.Fatalf("status = %d body = %s, want INVALID_REQUEST", recorder.Code, recorder.Body.String())
			}
		})
	}
}

// TestSupportHistoryWithoutSourceAnswersNotConfigured pins the 503 of a host without history source.
func TestSupportHistoryWithoutSourceAnswersNotConfigured(t *testing.T) {
	_, recorder := serve(testRouter(t, nil, bearer(definitions.ScopeHistoryRead), false),
		"/api/v1/support/authentication-attempts/search", searchBody())

	if recorder.Code != http.StatusServiceUnavailable || errorCode(t, recorder) != string(supporthistory.CodeNotConfigured) {
		t.Fatalf("status = %d body = %s, want HISTORY_NOT_CONFIGURED", recorder.Code, recorder.Body.String())
	}

	for _, secretField := range []string{"password_hash", "user_agent", "client_port"} {
		if strings.Contains(recorder.Body.String(), secretField) {
			t.Fatalf("body leaks %s", secretField)
		}
	}
}
