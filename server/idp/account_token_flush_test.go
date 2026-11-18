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

package idp

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/redisslot"
	"github.com/gin-gonic/gin"
)

const (
	// accountFlushTestAccount is the backend account name an operator passes to the admin user flush.
	accountFlushTestAccount = "alice"
	// accountFlushTestSubject is the backend unique user ID that becomes the token subject.
	accountFlushTestSubject = "7f3a2c1e-unique-user-id"
)

// accountFlushFixture issues real tokens on slot-guarded miniredis and runs the real admin user flush.
type accountFlushFixture struct {
	idp         *NauthilusIDP
	redisClient rediscli.Client
	cfg         *mockIdpConfig
}

// newAccountFlushFixture builds an IdP whose test client issues the requested access-token type.
func newAccountFlushFixture(t *testing.T, accessTokenType string) accountFlushFixture {
	t.Helper()

	_, handle, _ := redisslot.NewGuardedMiniredis(t, testRedisPrefix)
	redisClient := rediscli.NewTestClient(handle)
	cfg := idpTokenTestConfig()
	cfg.oidc.Clients[0].AccessTokenType = accessTokenType

	return accountFlushFixture{
		idp:         NewNauthilusIDP(&deps.Deps{Cfg: cfg, Redis: redisClient}),
		redisClient: redisClient,
		cfg:         cfg,
	}
}

// issue issues ID, access, and refresh tokens for a session whose subject differs from its account.
func (f accountFlushFixture) issue(t *testing.T) (string, string) {
	t.Helper()

	session := testOIDCSession([]string{definitions.ScopeOpenID, definitions.ScopeOfflineAccess}, time.Now().Add(-time.Minute))
	session.UserID = accountFlushTestSubject
	session.Username = accountFlushTestAccount

	_, accessToken, refreshToken, _, err := f.idp.IssueTokens(t.Context(), session)
	if err != nil || accessToken == "" || refreshToken == "" {
		t.Fatalf("IssueTokens() = access %q refresh %q, err %v", accessToken, refreshToken, err)
	}

	if _, err = f.idp.ValidateToken(t.Context(), accessToken); err != nil {
		t.Fatalf("fresh access token rejected: %v", err)
	}

	return accessToken, refreshToken
}

// flushAccount runs the admin user flush endpoint for one account with the IdP token storage as flusher.
func (f accountFlushFixture) flushAccount(t *testing.T, account string) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := core.NewUserFlushHandler(f.cfg, logger, f.redisClient, f.idp.storage)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/cache/flush", bytes.NewBufferString(`{"user":"`+account+`"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("user flush status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

// TestAdminUserFlushRevokesTokensOfAccountWithDistinctUniqueUserID reproduces the admin flush passing the
// account name where token storage expects the unique user ID: every token issued to the account's subject
// must be unusable after flushing the account.
func TestAdminUserFlushRevokesTokensOfAccountWithDistinctUniqueUserID(t *testing.T) {
	for _, accessTokenType := range []string{"jwt", accessTokenTypeOpaque} {
		t.Run(accessTokenType, func(t *testing.T) {
			fixture := newAccountFlushFixture(t, accessTokenType)
			accessToken, refreshToken := fixture.issue(t)

			fixture.flushAccount(t, accountFlushTestAccount)

			if _, err := fixture.idp.ValidateToken(t.Context(), accessToken); err == nil {
				t.Error("access token of the flushed account is still valid")
			}

			if _, _, _, _, _, err := fixture.idp.ExchangeRefreshToken(t.Context(), refreshToken, testClientID); err == nil {
				t.Error("refresh token of the flushed account can still be exchanged")
			}
		})
	}
}
