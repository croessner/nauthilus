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

package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnCeremonyStoreConsumesReferenceOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, mock := redismock.NewClientMock()
	deps := AuthDeps{
		Cfg:   &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}},
		Redis: rediscli.NewTestClient(db),
	}
	store, err := newWebAuthnCeremonyStore(deps)
	if err != nil {
		t.Fatalf("new ceremony store: %v", err)
	}

	mgr := &mockCookieManager{data: make(map[string]any)}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/login/webauthn/begin", nil)

	mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetVal("OK")
	if err = store.Store(ctx, mgr, webAuthnCeremonyLogin, &webauthn.SessionData{Challenge: "challenge"}); err != nil {
		t.Fatalf("store ceremony: %v", err)
	}

	reference := mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "")
	if reference == "" {
		t.Fatal("expected opaque ceremony reference in the browser session")
	}

	payload, err := jsonIter.Marshal(webAuthnCeremonyRecord{
		Kind:        webAuthnCeremonyLogin,
		Binding:     webAuthnCeremonyBinding(mgr, webAuthnCeremonyLogin),
		SessionData: webauthn.SessionData{Challenge: "challenge"},
	})
	if err != nil {
		t.Fatalf("marshal expected ceremony: %v", err)
	}

	mock.ExpectGetDel(store.redisKey(reference)).SetVal(string(payload))
	sessionData, err := store.Take(ctx, mgr, webAuthnCeremonyLogin)
	if err != nil {
		t.Fatalf("take ceremony: %v", err)
	}

	if sessionData.Challenge != "challenge" {
		t.Fatalf("challenge = %q, want challenge", sessionData.Challenge)
	}

	if mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "") != "" {
		t.Fatal("consumed ceremony reference remained in browser session")
	}

	mgr.Set(definitions.SessionKeyWebAuthnCeremony, reference)
	mock.ExpectGetDel(store.redisKey(reference)).RedisNil()
	if _, err = store.Take(ctx, mgr, webAuthnCeremonyLogin); err == nil {
		t.Fatal("expected a consumed ceremony reference to be rejected")
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations: %v", err)
	}
}
