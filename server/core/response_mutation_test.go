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

package core_test

import (
	"net/http/httptest"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"

	"github.com/gin-gonic/gin"
)

const (
	responseMutationAuthStatusHeader         = "Auth-Status"
	responseMutationAuthorizationHeader      = "Authorization"
	responseMutationConnectionHeader         = "Connection"
	responseMutationCookieHeader             = "Cookie"
	responseMutationHeader                   = "X-Nauthilus-Protection"
	responseMutationReasonHeader             = "X-Nauthilus-Protection-Reason"
	responseMutationSecretHeader             = "X-Secret-Password"
	responseMutationSelectedStatus           = "Plugin selected status"
	responseMutationSetCookieHeader          = "Set-Cookie"
	responseMutationStepupValue              = "stepup"
	responseMutationSecondValue              = "second"
	responseMutationProxyAuthorizationHeader = "Proxy-Authorization"
)

func TestPluginResponseMutationFiltersForbiddenHeaders(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	cfg.Server.DefaultHTTPRequestHeader.Password = responseMutationSecretHeader
	auth := newResponseAuthState(ctx, cfg, nil, definitions.ServJSON)

	auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
		Headers: pluginapi.ResponseHeaderMutation{
			Set: map[string][]string{
				responseMutationHeader:                   {responseMutationStepupValue},
				responseMutationSetCookieHeader:          {"session=leak"},
				responseMutationCookieHeader:             {"request-cookie=leak"},
				responseMutationAuthorizationHeader:      {"Bearer leak"},
				responseMutationProxyAuthorizationHeader: {"Basic leak"},
				responseMutationConnectionHeader:         {"upgrade"},
				responseMutationSecretHeader:             {"secret"},
			},
		},
	})

	header := recorder.Header()
	if got := header.Get(responseMutationHeader); got != responseMutationStepupValue {
		t.Fatalf("%s = %q, want stepup", responseMutationHeader, got)
	}

	for _, name := range []string{
		responseMutationSetCookieHeader,
		responseMutationCookieHeader,
		responseMutationAuthorizationHeader,
		responseMutationProxyAuthorizationHeader,
		responseMutationConnectionHeader,
		responseMutationSecretHeader,
	} {
		if got := header.Get(name); got != "" {
			t.Fatalf("forbidden response header %s = %q, want empty", name, got)
		}
	}
}

func TestPluginResponseMutationDuplicateAndDeleteBehavior(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	auth := newResponseAuthState(ctx, cfg, nil, definitions.ServJSON)

	auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
		Headers: pluginapi.ResponseHeaderMutation{
			Set: map[string][]string{
				responseMutationHeader:       {"first"},
				responseMutationReasonHeader: {"stale"},
			},
		},
	})
	auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
		Headers: pluginapi.ResponseHeaderMutation{
			Set: map[string][]string{
				responseMutationHeader: {responseMutationSecondValue},
			},
			Delete: []string{responseMutationReasonHeader},
		},
	})

	if values := recorder.Header().Values(responseMutationHeader); len(values) != 1 || values[0] != responseMutationSecondValue {
		t.Fatalf("%s values = %#v, want [second]", responseMutationHeader, values)
	}

	if got := recorder.Header().Get(responseMutationReasonHeader); got != "" {
		t.Fatalf("%s = %q, want deleted header", responseMutationReasonHeader, got)
	}
}

func TestPluginResponseMutationNoOpsWhenResponseIsNotMutable(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)

	t.Run("non HTTP service", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest("GET", "/auth", nil)

		cfg := &config.FileSettings{Server: &config.ServerSection{}}
		auth := newResponseAuthState(ctx, cfg, nil, definitions.ServGRPC)
		auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
			Headers: pluginapi.ResponseHeaderMutation{
				Set: map[string][]string{responseMutationHeader: {"ignored"}},
			},
		})

		if got := recorder.Header().Get(responseMutationHeader); got != "" {
			t.Fatalf("%s = %q, want no-op for gRPC", responseMutationHeader, got)
		}
	})

	t.Run("already written response", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest("GET", "/auth", nil)
		ctx.Writer.WriteHeaderNow()

		cfg := &config.FileSettings{Server: &config.ServerSection{}}
		auth := newResponseAuthState(ctx, cfg, nil, definitions.ServJSON)
		auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
			Headers: pluginapi.ResponseHeaderMutation{
				Set: map[string][]string{responseMutationHeader: {"too-late"}},
			},
		})

		if got := recorder.Header().Get(responseMutationHeader); got != "" {
			t.Fatalf("%s = %q, want no-op after write", responseMutationHeader, got)
		}
	})

	t.Run("explicitly disabled copied context", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest("GET", "/auth", nil)

		copiedCtx := ctx.Copy()
		copiedCtx.Set(definitions.CtxPluginResponseMutationDisabledKey, true)

		cfg := &config.FileSettings{Server: &config.ServerSection{}}
		auth := newResponseAuthState(copiedCtx, cfg, nil, definitions.ServJSON)
		auth.ApplyPluginResponseMutation(copiedCtx, pluginapi.ResponseMutation{
			Headers: pluginapi.ResponseHeaderMutation{
				Set: map[string][]string{responseMutationHeader: {"internal"}},
			},
		})

		if got := recorder.Header().Get(responseMutationHeader); got != "" {
			t.Fatalf("%s = %q, want no-op for explicitly disabled copied context", responseMutationHeader, got)
		}
	})
}

func TestPluginResponseMutationStatusHeaderUsesSelectedStatusMessage(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	auth := newResponseAuthState(ctx, cfg, nil, definitions.ServJSON)
	auth.Runtime.StatusMessage = responseMutationSelectedStatus

	auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
		Headers: pluginapi.ResponseHeaderMutation{
			Set: map[string][]string{responseMutationAuthStatusHeader: {"header override"}},
		},
		StatusHeader: true,
	})

	if got := recorder.Header().Get(responseMutationAuthStatusHeader); got != responseMutationSelectedStatus {
		t.Fatalf("Auth-Status = %q, want selected status message", got)
	}
}
