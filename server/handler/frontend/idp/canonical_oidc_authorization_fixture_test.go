// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/go-redis/redismock/v9"
)

const latchedConsentClientID = "test-client"

func latchedConsentOIDCClient() config.OIDCClient {
	return config.OIDCClient{
		ClientID:     latchedConsentClientID,
		ClientSecret: secret.New("test-secret"),
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{definitions.ScopeOpenID, "profile"},
	}
}

func newOIDCCallbackRedirectTestHandler(t *testing.T) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	return newOIDCCallbackRedirectTestHandlerWithClient(t, latchedConsentOIDCClient())
}

func newOIDCCallbackRedirectTestHandlerWithClient(
	t *testing.T,
	client config.OIDCClient,
) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients:    []config.OIDCClient{client},
	}
	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	return NewOIDCHandler(d, idp.NewNauthilusIDP(d), nil), mock
}

func expectOIDCAuthorizationCodeStorage(mock redismock.ClientMock) {
	mock.Regexp().ExpectSet("test:oidc:code:.*", ".*", 10*time.Minute).SetVal("OK")
}
