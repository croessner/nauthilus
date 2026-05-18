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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	_ "github.com/croessner/nauthilus/server/core/auth"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/encoding/cborcodec"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/model/authdto"
	"github.com/croessner/nauthilus/server/openapi/requesttest"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
)

const (
	authResponseContractBackendName = "response_contract"
	authResponseContractPassword    = "synthetic-response-password"
	authResponseAuthPortHeader      = "Auth-Port"
	authResponseAuthServerHeader    = "Auth-Server"
	authResponseAuthStatusHeader    = "Auth-Status"
	authResponseBackendAddress      = "imap.backend.test"
	authResponseCacheHeader         = "X-Nauthilus-Memory-Cache"
	authResponseCacheMiss           = "Miss"
	authResponseHeaderOK            = "OK"
	authResponseMediaJSON           = "application/json"
	authResponseMethodPlain         = "plain"
	authResponseSessionHeader       = "X-Nauthilus-Session"
	authResponseUserAgent           = "contract-test"
	authResponseWaitHeader          = "Auth-Wait"
)

type authResponseContractCase struct {
	assertBody         func(t *testing.T, body []byte)
	request            func(t *testing.T, username string) *http.Request
	validation         requesttest.ResponseValidation
	name               string
	username           string
	protocol           string
	expectedAuthServer string
	expectedAuthPort   string
}

var authResponseContractCases = []authResponseContractCase{
	{
		name:     "json",
		username: "json-response@example.test",
		protocol: definitions.ProtoIMAP,
		request: func(_ *testing.T, username string) *http.Request {
			return requesttest.NewJSONRequest(http.MethodPost, "/api/v1/auth/json?cache=0&in-memory=0", authResponseContractJSONBody(username, authResponseContractPassword))
		},
		validation: requesttest.ResponseValidation{
			ExpectedMediaType: authResponseMediaJSON,
		},
		assertBody: assertAuthJSONSuccessBody,
	},
	{
		name:     "cbor",
		username: "cbor-response@example.test",
		protocol: definitions.ProtoIMAP,
		request:  newAuthResponseCBORRequest,
		validation: requesttest.ResponseValidation{
			ExpectedMediaType: "application/cbor",
			ExcludeBody:       true,
		},
		assertBody: assertAuthCBORSuccessBody,
	},
	{
		name:     "header",
		username: "header-response@example.test",
		protocol: definitions.ProtoIMAP,
		request:  newAuthResponseHeaderRequest("/api/v1/auth/header?cache=0&in-memory=0"),
		validation: requesttest.ResponseValidation{
			ExcludeBody: true,
		},
		assertBody: assertEmptyAuthBody,
	},
	{
		name:               "nginx",
		username:           "nginx-response@example.test",
		protocol:           definitions.ProtoIMAP,
		request:            newAuthResponseHeaderRequest("/api/v1/auth/nginx?cache=0&in-memory=0"),
		expectedAuthServer: authResponseBackendAddress,
		expectedAuthPort:   "993",
		validation: requesttest.ResponseValidation{
			ExcludeBody: true,
		},
		assertBody: assertEmptyAuthBody,
	},
}

func TestAuthHandlerResponsesMatchOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tt := range authResponseContractCases {
		t.Run(tt.name, func(t *testing.T) {
			runAuthResponseContractCase(t, tt)
		})
	}
}

func runAuthResponseContractCase(t *testing.T, tt authResponseContractCase) {
	t.Helper()

	router, mock, cfg := newAuthResponseContractRouter(t, authResponseContractBackendName+"_"+tt.name)
	request := tt.request(t, tt.username)
	recorder := httptest.NewRecorder()

	expectAuthAccountMappingSync(mock, cfg, tt.username, tt.protocol, tt.username)

	router.ServeHTTP(recorder, request)

	validation := authResponseValidationFor(tt)

	requesttest.AssertRecorderResponse(t, requesttest.NewManagementValidator(t), request, recorder, validation)
	tt.assertBody(t, recorder.Body.Bytes())

	if strings.Contains(recorder.Body.String(), authResponseContractPassword) {
		t.Fatalf("auth response body exposed request password")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func authResponseValidationFor(tt authResponseContractCase) requesttest.ResponseValidation {
	validation := tt.validation
	validation.RequiredHeaderValues = map[string]string{
		authResponseAuthStatusHeader: authResponseHeaderOK,
		authContractHeaderUsername:   tt.username,
		authResponseCacheHeader:      authResponseCacheMiss,
	}

	if tt.expectedAuthServer != "" {
		validation.RequiredHeaderValues[authResponseAuthServerHeader] = tt.expectedAuthServer
		validation.RequiredHeaderValues[authResponseAuthPortHeader] = tt.expectedAuthPort
	}

	validation.RequiredHeaders = append(validation.RequiredHeaders, authResponseSessionHeader)

	return validation
}

func newAuthResponseCBORRequest(t *testing.T, username string) *http.Request {
	t.Helper()

	payload, err := cborcodec.Marshal(authdto.Request{
		Username:  username,
		Password:  authResponseContractPassword,
		ClientIP:  authContractClientIP,
		Protocol:  definitions.ProtoIMAP,
		Method:    authResponseMethodPlain,
		UserAgent: authResponseUserAgent,
	})
	if err != nil {
		t.Fatalf("marshal CBOR auth request: %v", err)
	}

	return requesttest.NewRequest(http.MethodPost, "/api/v1/auth/cbor?cache=0&in-memory=0", "application/cbor", string(payload))
}

func newAuthResponseHeaderRequest(path string) func(*testing.T, string) *http.Request {
	return func(_ *testing.T, username string) *http.Request {
		return requesttest.WithHeaders(
			requesttest.NewRequest(http.MethodGet, path, "", ""),
			authResponseContractHeaders(username, authResponseContractPassword, definitions.ProtoIMAP),
		)
	}
}

func TestAuthNginxFailureResponseIncludesWaitHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router, mock, cfg := newAuthResponseContractRouter(t, authResponseContractBackendName+"_nginx_failure")
	username := "nginx-failure-response@example.test"
	validator := requesttest.NewManagementValidator(t)

	successRequest := requesttest.WithHeaders(
		requesttest.NewRequest(http.MethodGet, "/api/v1/auth/nginx?cache=0&in-memory=0", "", ""),
		authResponseContractHeaders(username, authResponseContractPassword, definitions.ProtoIMAP),
	)
	successRecorder := httptest.NewRecorder()

	expectAuthAccountMappingSync(mock, cfg, username, definitions.ProtoIMAP, username)

	router.ServeHTTP(successRecorder, successRequest)

	requesttest.AssertRecorderResponse(t, validator, successRequest, successRecorder, requesttest.ResponseValidation{
		RequiredHeaderValues: map[string]string{
			authResponseAuthStatusHeader: authResponseHeaderOK,
			authContractHeaderUsername:   username,
			authResponseAuthServerHeader: authResponseBackendAddress,
			authResponseAuthPortHeader:   "993",
			authResponseCacheHeader:      authResponseCacheMiss,
		},
		RequiredHeaders: []string{authResponseSessionHeader},
		ExcludeBody:     true,
	})

	failureRequest := requesttest.WithHeaders(
		requesttest.NewRequest(http.MethodGet, "/api/v1/auth/nginx?cache=0&in-memory=0", "", ""),
		authResponseContractHeaders(username, "wrong-synthetic-response-password", definitions.ProtoIMAP),
	)
	failureRecorder := httptest.NewRecorder()

	expectAuthAccountMappingSync(mock, cfg, username, definitions.ProtoIMAP, username)

	router.ServeHTTP(failureRecorder, failureRequest)

	requesttest.AssertRecorderResponse(t, validator, failureRequest, failureRecorder, requesttest.ResponseValidation{
		ExpectedMediaType: authResponseMediaJSON,
		RequiredHeaderValues: map[string]string{
			authResponseAuthStatusHeader: definitions.PasswordFail,
		},
		RequiredHeaders: []string{authResponseWaitHeader, authResponseSessionHeader},
	})
	assertAuthFailureNullBody(t, failureRecorder.Body.Bytes())

	if strings.Contains(failureRecorder.Body.String(), "wrong-synthetic-response-password") {
		t.Fatalf("auth failure response body exposed request password")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func newAuthResponseContractRouter(t *testing.T, backendName string) (*gin.Engine, redismock.ClientMock, config.File) {
	t.Helper()

	core.InitPassDBResultPool()

	var backend config.Backend
	if err := backend.Set(fmt.Sprintf("%s(%s)", definitions.BackendTestName, backendName)); err != nil {
		t.Fatalf("configure test backend: %v", err)
	}

	env := config.NewTestEnvironmentConfig()
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Backends: []*config.Backend{&backend},
			Redis:    config.Redis{Prefix: "t:", NegCacheTTL: time.Hour},
			DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
				Username:     authContractHeaderUsername,
				Password:     authContractHeaderPassword,
				Protocol:     authContractHeaderProtocol,
				AuthMethod:   authContractHeaderMethod,
				LoginAttempt: authContractHeaderLoginAttempt,
				ClientIP:     authContractHeaderClientIP,
			},
			IMAPBackendAddress: authResponseBackendAddress,
			IMAPBackendPort:    993,
			NginxWaitDelay:     5,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config.SetTestEnvironmentConfig(env)
	config.SetTestFile(cfg)
	core.SetDefaultConfigFile(cfg)
	core.SetDefaultEnvironment(env)
	core.SetDefaultLogger(logger)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(env)
	util.SetDefaultLogger(logger)

	db, mock := redismock.NewClientMock()
	mock.MatchExpectationsInOrder(true)

	deps := &handlerdeps.Deps{
		Cfg:    cfg,
		Env:    env,
		Logger: logger,
		Redis:  rediscli.NewTestClient(db),
	}

	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxGUIDKey, "response-contract-session")
		ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
		ctx.Next()
	})
	New(deps).Register(router.Group("/api/v1"))

	return router, mock, cfg
}

func expectAuthAccountMappingSync(mock redismock.ClientMock, cfg config.File, username, protocol, account string) {
	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	mock.ExpectHGet(key, field).SetErr(redis.Nil)
	mock.ExpectHGet(key, field).SetErr(redis.Nil)
	mock.ExpectHSet(key, field, account).SetVal(1)
	mock.ExpectHGet(key, field).SetVal(account)
}

func authResponseContractJSONBody(username, password string) string {
	return fmt.Sprintf(
		`{"username":%q,"password":%q,"client_ip":%q,"protocol":"imap","method":%q,"user_agent":%q}`,
		username,
		password,
		authContractClientIP,
		authResponseMethodPlain,
		authResponseUserAgent,
	)
}

func authResponseContractHeaders(username, password, protocol string) map[string]string {
	return map[string]string{
		authContractHeaderUsername: username,
		authContractHeaderPassword: password,
		authContractHeaderProtocol: protocol,
		authContractHeaderMethod:   authResponseMethodPlain,
		authContractHeaderClientIP: authContractClientIP,
		"User-Agent":               authResponseUserAgent,
	}
}

func assertAuthJSONSuccessBody(t *testing.T, body []byte) {
	t.Helper()

	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("auth JSON response body is not JSON: %v", err)
	}

	assertAuthSuccessEnvelope(t, document)
}

func assertAuthCBORSuccessBody(t *testing.T, body []byte) {
	t.Helper()

	var document map[string]any
	if err := cborcodec.Unmarshal(body, &document); err != nil {
		t.Fatalf("auth CBOR response body is not CBOR: %v", err)
	}

	assertAuthSuccessEnvelope(t, document)
}

func assertAuthSuccessEnvelope(t *testing.T, document map[string]any) {
	t.Helper()

	if ok, _ := document["ok"].(bool); !ok {
		t.Fatalf("auth response ok = %#v, want true", document["ok"])
	}

	for _, field := range []string{"account_field", "backend", "attributes"} {
		if _, ok := document[field]; !ok {
			t.Fatalf("auth response field %q missing in %#v", field, document)
		}
	}
}

func assertEmptyAuthBody(t *testing.T, body []byte) {
	t.Helper()

	if len(strings.TrimSpace(string(body))) != 0 {
		t.Fatalf("auth header-only body = %q, want empty body", string(body))
	}
}

func assertAuthFailureNullBody(t *testing.T, body []byte) {
	t.Helper()

	if strings.TrimSpace(string(body)) != "null" {
		t.Fatalf("auth failure body = %q, want JSON null", string(body))
	}
}
