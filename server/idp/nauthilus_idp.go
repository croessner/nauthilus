// Copyright (C) 2025 Christian Rößner
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
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp/dcr"
	"github.com/croessner/nauthilus/v3/server/idp/oidckeys"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// NauthilusIDP provides the canonical OIDC and SAML identity services.
type NauthilusIDP struct {
	deps            *deps.Deps
	storage         *RedisTokenStorage
	tracer          monittrace.Tracer
	keyMgr          *oidckeys.Manager
	tokenGen        TokenGenerator
	dynamicClients  *dcr.Repository
	authApplication *idpAuthApplicationBridge
}

var (
	// ErrInvalidRefreshToken indicates the submitted refresh token was unknown or expired.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrRefreshTokenClientMismatch indicates the refresh token was not issued to the requesting client.
	ErrRefreshTokenClientMismatch = errors.New("refresh token client mismatch")
)

// NewNauthilusIDP creates a new instance of NauthilusIDP.
func NewNauthilusIDP(d *deps.Deps) *NauthilusIDP {
	prefix := d.Cfg.GetServer().GetRedis().GetPrefix()
	dynamicPolicy := d.Cfg.GetIDP().OIDC.DynamicClientRegistration

	return &NauthilusIDP{
		deps:            d,
		storage:         NewRedisTokenStorageWithConfig(d.Redis, prefix, d.Cfg, dcr.NewSlogAuditor(d.Logger)),
		tracer:          monittrace.New("nauthilus/idp"),
		keyMgr:          oidckeys.NewManager(d),
		tokenGen:        NewDefaultTokenGenerator(),
		dynamicClients:  dcr.NewRepository(d.Redis, prefix, dynamicPolicy.GetLifecycle(), dcr.NewSlogAuditor(d.Logger)),
		authApplication: newIDPAuthApplicationBridge(d),
	}
}

// GetKeyManager returns the OIDC key manager.
func (n *NauthilusIDP) GetKeyManager() *oidckeys.Manager {
	return n.keyMgr
}

// FilterScopes filters the requested scopes against the allowed scopes for the client.
func (n *NauthilusIDP) FilterScopes(client *config.OIDCClient, requestedScopes []string) []string {
	allowed := client.GetAllowedScopes()
	impliedScopes := client.GetImpliedScopes()
	allowedMap := allowedScopeSet(allowed)
	filtered, seen := filterRequestedScopes(requestedScopes, allowedMap, len(impliedScopes))

	return n.appendImpliedScopes(filtered, seen, allowedMap, impliedScopes, oidcClientID(client))
}

// allowedScopeSet builds the normalized allowed-scope lookup.
func allowedScopeSet(allowed []string) map[string]struct{} {
	allowedMap := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		scope := strings.TrimSpace(s)
		if scope == "" {
			continue
		}

		allowedMap[scope] = struct{}{}
	}

	return allowedMap
}

// filterRequestedScopes returns requested scopes allowed for the client.
func filterRequestedScopes(requestedScopes []string, allowedMap map[string]struct{}, impliedCount int) ([]string, map[string]struct{}) {
	filtered := make([]string, 0, len(requestedScopes)+impliedCount)
	seen := make(map[string]struct{}, len(requestedScopes)+impliedCount)

	for _, rs := range requestedScopes {
		scope := strings.TrimSpace(rs)
		if scope == "" {
			continue
		}

		if _, ok := allowedMap[scope]; !ok {
			continue
		}

		if _, exists := seen[scope]; exists {
			continue
		}

		seen[scope] = struct{}{}
		filtered = append(filtered, scope)
	}

	return filtered, seen
}

// appendImpliedScopes appends valid implied scopes and logs invalid client configuration.
func (n *NauthilusIDP) appendImpliedScopes(
	filtered []string,
	seen map[string]struct{},
	allowedMap map[string]struct{},
	impliedScopes []string,
	clientID string,
) []string {
	for _, implied := range impliedScopes {
		scope := strings.TrimSpace(implied)
		if scope == "" {
			continue
		}

		if _, ok := allowedMap[scope]; !ok {
			if n != nil && n.deps != nil && n.deps.Logger != nil {
				n.deps.Logger.Warn(
					"Ignoring implied scope not listed in client allowed scopes",
					"client_id", clientID,
					"scope", scope,
				)
			}

			continue
		}

		if _, exists := seen[scope]; exists {
			continue
		}

		seen[scope] = struct{}{}
		filtered = append(filtered, scope)
	}

	return filtered
}

// oidcClientID returns the configured client id for logging.
func oidcClientID(client *config.OIDCClient) string {
	if client == nil {
		return ""
	}

	return client.ClientID
}

// FindClient returns an OIDC client by its ID.
func (n *NauthilusIDP) FindClient(clientID string) (*config.OIDCClient, bool) {
	clients := n.deps.Cfg.GetIDP().OIDC.Clients
	for index := range clients {
		if clients[index].ClientID == clientID {
			return &clients[index], true
		}
	}

	return nil, false
}

// ResolveClient returns a static client or authoritatively resolves a dynamic client.
func (n *NauthilusIDP) ResolveClient(ctx context.Context, clientID string) (*config.OIDCClient, error) {
	if client, ok := n.FindClient(clientID); ok {
		return client, nil
	}

	registration := n.deps.Cfg.GetIDP().OIDC.DynamicClientRegistration
	if !registration.Enabled || !strings.HasPrefix(clientID, dcr.ClientIDPrefix) {
		return nil, dcr.ErrNotFound
	}

	record, err := n.dynamicClients.Get(ctx, clientID)
	if err != nil {
		return nil, err
	}

	return dcr.NewRuntimePolicy(registration).Resolve(record)
}

// TouchDynamicClient records activity after successful protocol validation.
func (n *NauthilusIDP) TouchDynamicClient(ctx context.Context, client *config.OIDCClient, operation string) error {
	if client == nil || !client.Dynamic {
		return nil
	}

	if err := n.dynamicClients.Touch(ctx, client.ClientID); err != nil {
		n.auditDynamicClient(ctx, operation, "failed", "touch_failed", client.ClientID)

		return err
	}

	n.auditDynamicClient(ctx, operation, "success", "validated_use", client.ClientID)

	return nil
}

// auditDynamicClient records bounded profile use without user or redirect metadata.
func (n *NauthilusIDP) auditDynamicClient(ctx context.Context, operation string, outcome string, reason string, clientID string) {
	dcr.NewSlogAuditor(n.deps.Logger).Record(ctx, dcr.AuditEvent{
		Operation: operation,
		Outcome:   outcome,
		Reason:    reason,
		ClientID:  clientID,
	})
}

// FindSAMLServiceProvider returns a SAML service provider by its entity ID.
func (n *NauthilusIDP) FindSAMLServiceProvider(entityID string) (*config.SAML2ServiceProvider, bool) {
	return config.FindSAMLServiceProviderByEntityID(n.deps.Cfg.GetIDP().SAML2.ServiceProviders, entityID)
}

// IsDelayedResponse returns true if delayed response is enabled for the given client.
func (n *NauthilusIDP) IsDelayedResponse(clientID string, samlEntityID string) bool {
	if clientID != "" {
		if client, ok := n.FindClient(clientID); ok {
			return client.IsDelayedResponse()
		}
	}

	if samlEntityID != "" {
		if sp, ok := n.FindSAMLServiceProvider(samlEntityID); ok {
			return sp.IsDelayedResponse()
		}
	}

	return false
}

// ValidateRedirectURI checks if the given redirect URI is valid for the client.
func (n *NauthilusIDP) ValidateRedirectURI(client *config.OIDCClient, redirectURI string) bool {
	if client == nil {
		return false
	}

	if client.Dynamic {
		return dcr.MatchRedirectURI(client.RedirectURIs, redirectURI)
	}

	return validateRedirectURIAgainstAllowList(client.RedirectURIs, redirectURI)
}

// ValidatePostLogoutRedirectURI checks if the given post-logout redirect URI is valid for the client.
func (n *NauthilusIDP) ValidatePostLogoutRedirectURI(client *config.OIDCClient, redirectURI string) bool {
	if redirectURI == "" {
		return true
	}

	return slices.Contains(client.PostLogoutRedirectURIs, redirectURI)
}

// IssueTokens generates tokens for the given OIDC session.
// Per OIDC Core 1.0 §3.1.2.1, an ID token is only issued when the "openid" scope is present.
// Without "openid", this behaves as a pure OAuth 2.0 token response (access_token only).
func (n *NauthilusIDP) IssueTokens(ctx context.Context, session *OIDCSession) (string, string, string, time.Duration, error) {
	client, err := n.ResolveClient(ctx, session.ClientID)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("client not found")
	}

	if client.Dynamic {
		if err := n.validateDynamicSessionPolicy(client, session); err != nil {
			return "", "", "", 0, err
		}

		epoch, err := n.storage.DynamicUserEpoch(ctx, session.UserID)
		if err != nil {
			return "", "", "", 0, fmt.Errorf("load dynamic token revocation epoch: %w", err)
		}

		session.DynamicUserEpoch = epoch
	}

	return n.issueTokensForClient(ctx, client, session, "")
}

// validateDynamicSessionPolicy rejects stale sessions after operator-policy narrowing.
func (n *NauthilusIDP) validateDynamicSessionPolicy(client *config.OIDCClient, session *OIDCSession) error {
	if client == nil || session == nil || !client.Dynamic {
		return nil
	}

	filteredScopes := n.FilterScopes(client, session.Scopes)
	if !slices.Equal(filteredScopes, session.Scopes) || client.RequiredMFALevel > session.RequiredMFALevel {
		return fmt.Errorf("dynamic client policy changed; authorization must restart")
	}

	if slices.Contains(session.Scopes, definitions.ScopeOfflineAccess) && !client.SupportsGrantType(dcr.GrantRefreshToken) {
		return fmt.Errorf("dynamic client refresh policy changed; authorization must restart")
	}

	return nil
}

func (n *NauthilusIDP) issueTokensForClient(
	ctx context.Context,
	client *config.OIDCClient,
	session *OIDCSession,
	persistedRefreshToken string,
) (string, string, string, time.Duration, error) {
	idTokenString, accessTokenString, accessTokenLifetime, err := n.issueIDAndAccessTokens(ctx, client, session)
	if err != nil {
		return "", "", "", 0, err
	}

	refreshTokenString := ""
	hasOfflineAccess := slices.Contains(session.Scopes, definitions.ScopeOfflineAccess)

	if hasOfflineAccess {
		if client.Dynamic {
			refreshTokenString, err = n.storeInitialDynamicRefreshToken(ctx, client, session, accessTokenString)
			if err != nil {
				_ = n.storage.DeleteAccessToken(ctx, accessTokenString)

				return "", "", "", 0, err
			}

			return idTokenString, accessTokenString, refreshTokenString, accessTokenLifetime, nil
		}

		refreshTokenString, err = n.storeRefreshTokenSession(ctx, client, persistedRefreshToken, session, accessTokenString)
		if err != nil {
			return "", "", "", 0, err
		}

		if persistedRefreshToken != "" {
			refreshTokenString = ""
		}
	}

	return idTokenString, accessTokenString, refreshTokenString, accessTokenLifetime, nil
}

// storeInitialDynamicRefreshToken creates the first rotating token and family pointer.
func (n *NauthilusIDP) storeInitialDynamicRefreshToken(ctx context.Context, client *config.OIDCClient, session *OIDCSession, accessToken string) (string, error) {
	refreshToken, err := n.tokenGen.GenerateToken(definitions.OIDCTokenPrefixRefreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	familyID, err := n.tokenGen.GenerateToken("dcr_family_")
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh family: %w", err)
	}

	session.AccessToken = accessToken
	session.RefreshFamilyID = familyID

	if err := n.storage.StoreInitialDynamicRefreshToken(ctx, refreshToken, session, client.RefreshTokenLifetime); err != nil {
		return "", fmt.Errorf("failed to store dynamic refresh token: %w", err)
	}

	return refreshToken, nil
}

func (n *NauthilusIDP) issueIDAndAccessTokens(
	ctx context.Context,
	client *config.OIDCClient,
	session *OIDCSession,
) (string, string, time.Duration, error) {
	_, sp := n.tracer.Start(ctx, "idp.issue_tokens",
		attribute.String("client_id", session.ClientID),
		attribute.String("user_id", session.UserID),
	)
	defer sp.End()

	accessTokenLifetime := client.AccessTokenLifetime
	if accessTokenLifetime == 0 {
		accessTokenLifetime = n.deps.Cfg.GetIDP().OIDC.GetDefaultAccessTokenLifetime()
	}

	issuer := n.deps.Cfg.GetIDP().OIDC.Issuer

	signer, err := n.keyMgr.GetActiveSigner(ctx, "")
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to get active signing key: %w", err)
	}

	now := time.Now()

	idTokenString, err := n.issueIDToken(session, signer, issuer, now, accessTokenLifetime)
	if err != nil {
		sp.RecordError(err)

		return "", "", 0, err
	}

	// Access Token
	tokenIssuer := NewTokenIssuer(issuer, signer, session, n.storage, n.tokenGen)
	accessTokenType := client.GetAccessTokenType(n.deps.Cfg.GetIDP().OIDC.GetAccessTokenType())

	var accessTokenString string

	if accessTokenType == accessTokenTypeOpaque {
		accessTokenString, _, err = tokenIssuer.IssueOpaque(ctx, accessTokenLifetime)
	} else {
		accessTokenString, _, err = tokenIssuer.IssueJWT(ctx, accessTokenLifetime)
	}

	if err != nil {
		sp.RecordError(err)

		return "", "", 0, err
	}

	return idTokenString, accessTokenString, accessTokenLifetime, nil
}

func (n *NauthilusIDP) issueIDToken(
	session *OIDCSession,
	signer signing.Signer,
	issuer string,
	now time.Time,
	accessTokenLifetime time.Duration,
) (string, error) {
	if !slices.Contains(session.Scopes, definitions.ScopeOpenID) {
		return "", nil
	}

	idClaims := jwt.MapClaims{
		oidcClaimIssuer:    issuer,
		oidcClaimSubject:   session.UserID,
		oidcClaimAudience:  session.ClientID,
		oidcClaimExpiresAt: now.Add(accessTokenLifetime).Unix(),
		oidcClaimIssuedAt:  now.Unix(),
		"auth_time":        session.AuthTime.Unix(),
	}

	if session.Nonce != "" {
		idClaims["nonce"] = session.Nonce
	}

	copyCustomIDTokenClaims(idClaims, session.IDTokenClaims)

	idTokenString, err := signer.Sign(idClaims)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return idTokenString, nil
}

func (n *NauthilusIDP) storeRefreshTokenSession(
	ctx context.Context,
	client *config.OIDCClient,
	refreshToken string,
	session *OIDCSession,
	accessToken string,
) (string, error) {
	if refreshToken == "" {
		generatedRefreshToken, err := n.tokenGen.GenerateToken(definitions.OIDCTokenPrefixRefreshToken)
		if err != nil {
			return "", fmt.Errorf("failed to generate refresh token: %w", err)
		}

		refreshToken = generatedRefreshToken
	}

	refreshTokenLifetime := client.RefreshTokenLifetime
	if refreshTokenLifetime == 0 {
		refreshTokenLifetime = n.deps.Cfg.GetIDP().OIDC.GetDefaultRefreshTokenLifetime()
	}

	// Link the access token to the refresh token session so it can be
	// invalidated during token rotation or reuse.
	session.AccessToken = accessToken

	err := n.storage.StoreRefreshToken(ctx, refreshToken, session, refreshTokenLifetime)
	if err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return refreshToken, nil
}

// IssueClientCredentialsToken generates an access token for the Client Credentials Grant.
// Per RFC 6749 §4.4, only an access token is returned (no id_token, no refresh_token).
func (n *NauthilusIDP) IssueClientCredentialsToken(ctx context.Context, clientID string, scopes []string) (string, time.Duration, error) {
	_, sp := n.tracer.Start(ctx, "idp.issue_client_credentials_token",
		attribute.String("client_id", clientID),
	)
	defer sp.End()

	client, ok := n.FindClient(clientID)
	if !ok {
		return "", 0, fmt.Errorf("client not found")
	}

	if !client.SupportsGrantType("client_credentials") {
		return "", 0, fmt.Errorf("client does not support client_credentials grant type")
	}

	if client.IsPublicClient() {
		return "", 0, fmt.Errorf("client_credentials requires confidential client authentication")
	}

	resource, err := classifyClientCredentialsScopes(scopes)
	if err != nil {
		return "", 0, err
	}

	accessTokenLifetime := client.AccessTokenLifetime

	if accessTokenLifetime == 0 {
		accessTokenLifetime = n.deps.Cfg.GetIDP().OIDC.GetDefaultAccessTokenLifetime()
	}

	issuer := n.deps.Cfg.GetIDP().OIDC.Issuer

	signer, err := n.keyMgr.GetActiveSigner(ctx, "")
	if err != nil {
		sp.RecordError(err)

		return "", 0, fmt.Errorf("failed to get active signing key: %w", err)
	}

	// Build a service-token session without browser or user-flow state.
	session := &OIDCSession{
		ClientID:            clientID,
		UserID:              clientID,
		Scopes:              slices.Clone(scopes),
		AuthTime:            time.Now(),
		AccessTokenAudience: resource.audience(),
		AccessTokenIssuer:   issuer,
		AccessTokenClaims:   make(map[string]any),
		ServiceToken:        true,
	}

	// Access Token
	tokenIssuer := NewTokenIssuer(issuer, signer, session, n.storage, n.tokenGen)
	accessTokenType := client.GetAccessTokenType(n.deps.Cfg.GetIDP().OIDC.GetAccessTokenType())

	var accessTokenString string

	if accessTokenType == accessTokenTypeOpaque {
		accessTokenString, _, err = tokenIssuer.IssueOpaque(ctx, accessTokenLifetime)
	} else {
		accessTokenString, _, err = tokenIssuer.IssueJWT(ctx, accessTokenLifetime)
	}

	if err != nil {
		sp.RecordError(err)

		return "", 0, err
	}

	return accessTokenString, accessTokenLifetime, nil
}

// ExchangeRefreshToken exchanges a refresh token for a new set of tokens.
func (n *NauthilusIDP) ExchangeRefreshToken(ctx context.Context, refreshToken string, clientID string) (*OIDCSession, string, string, string, time.Duration, error) {
	_, sp := n.tracer.Start(ctx, "idp.exchange_refresh_token",
		attribute.String("client_id", clientID),
	)
	defer sp.End()

	if strings.HasPrefix(clientID, dcr.ClientIDPrefix) {
		return n.exchangeDynamicRefreshToken(ctx, refreshToken, clientID)
	}

	session, err := n.storage.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, "", "", "", 0, fmt.Errorf("%w", ErrInvalidRefreshToken)
	}

	if session.ClientID != clientID {
		return nil, "", "", "", 0, fmt.Errorf("%w", ErrRefreshTokenClientMismatch)
	}

	client, resolveErr := n.ResolveClient(ctx, clientID)
	if resolveErr != nil {
		return nil, "", "", "", 0, fmt.Errorf("client not found")
	}

	rotateRefreshTokens := client.GetRevokeRefreshToken(n.deps.Cfg.GetIDP().OIDC.GetRevokeRefreshToken())

	// Invalidate the access token that was last bound to this refresh token
	// session before issuing the replacement access token.
	n.invalidateOldAccessToken(ctx, session, clientID)

	if rotateRefreshTokens {
		_ = n.storage.DeleteRefreshToken(ctx, refreshToken)
	}

	// Clear the old access token reference before issuing new tokens.
	session.AccessToken = ""

	persistedRefreshToken := ""
	if !rotateRefreshTokens {
		persistedRefreshToken = refreshToken
	}

	idToken, accessToken, newRefreshToken, expiresIn, issueErr := n.issueTokensForClient(ctx, client, session, persistedRefreshToken)
	if issueErr != nil {
		return nil, "", "", "", 0, issueErr
	}

	return session, idToken, accessToken, newRefreshToken, expiresIn, nil
}

// exchangeDynamicRefreshToken rotates a public-native refresh family atomically.
func (n *NauthilusIDP) exchangeDynamicRefreshToken(ctx context.Context, refreshToken string, clientID string) (*OIDCSession, string, string, string, time.Duration, error) { //nolint:gocyclo
	session, err := n.storage.GetDynamicRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, redis.Nil) || errors.Is(err, ErrDynamicRefreshTokenReuse) {
			return nil, "", "", "", 0, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
		}

		return nil, "", "", "", 0, err
	}

	if session.ClientID != clientID {
		return nil, "", "", "", 0, fmt.Errorf("%w", ErrRefreshTokenClientMismatch)
	}

	client, err := n.ResolveClient(ctx, clientID)
	if err != nil || !client.Dynamic || !client.SupportsGrantType(dcr.GrantRefreshToken) || session.RefreshFamilyID == "" {
		return nil, "", "", "", 0, fmt.Errorf("client not found")
	}

	if err := n.validateDynamicSessionPolicy(client, session); err != nil {
		return nil, "", "", "", 0, fmt.Errorf("%w: %v", ErrInvalidRefreshToken, err)
	}

	n.invalidateOldAccessToken(ctx, session, clientID)
	session.AccessToken = ""

	idToken, accessToken, expiresIn, err := n.issueIDAndAccessTokens(ctx, client, session)
	if err != nil {
		return nil, "", "", "", 0, err
	}

	newRefreshToken, err := n.tokenGen.GenerateToken(definitions.OIDCTokenPrefixRefreshToken)
	if err != nil {
		_ = n.storage.DeleteAccessToken(ctx, accessToken)

		return nil, "", "", "", 0, err
	}

	session.AccessToken = accessToken
	if err := n.storage.RotateDynamicRefreshToken(ctx, refreshToken, newRefreshToken, session, client.RefreshTokenLifetime); err != nil {
		_ = n.storage.DeleteAccessToken(ctx, accessToken)

		if errors.Is(err, redis.Nil) || errors.Is(err, ErrDynamicRefreshTokenReuse) {
			return nil, "", "", "", 0, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
		}

		return nil, "", "", "", 0, err
	}

	if err := n.TouchDynamicClient(ctx, client, "refresh_exchange"); err != nil {
		_ = n.storage.DeleteAccessToken(ctx, accessToken)
		_ = n.storage.DeleteDynamicRefreshToken(ctx, newRefreshToken)

		return nil, "", "", "", 0, err
	}

	return session, idToken, accessToken, newRefreshToken, expiresIn, nil
}

// invalidateOldAccessToken removes the previous access token that was linked
// to the refresh token session. For opaque tokens it deletes the Redis entry;
// for JWT tokens it adds the token to a denylist with the remaining lifetime.
func (n *NauthilusIDP) invalidateOldAccessToken(ctx context.Context, session *OIDCSession, clientID string) {
	oldAccessToken := session.AccessToken

	if oldAccessToken == "" {
		return
	}

	// Opaque tokens do not contain dots; JWT tokens always do.
	if !strings.Contains(oldAccessToken, ".") {
		_ = n.storage.DeleteAccessToken(ctx, oldAccessToken)

		return
	}

	// JWT token: add to denylist with the client's access token lifetime
	// as a conservative upper bound for the remaining validity.
	client, ok := n.FindClient(clientID)
	if !ok {
		return
	}

	ttl := client.AccessTokenLifetime

	if ttl == 0 {
		ttl = n.deps.Cfg.GetIDP().OIDC.GetDefaultAccessTokenLifetime()
	}

	_ = n.storage.DenyJWTAccessToken(ctx, oldAccessToken, ttl)
}

// IssueLogoutToken generates a logout token for the given client and user.
func (n *NauthilusIDP) IssueLogoutToken(ctx context.Context, clientID string, userID string) (string, error) {
	_, sp := n.tracer.Start(ctx, "idp.issue_logout_token",
		attribute.String("client_id", clientID),
		attribute.String("user_id", userID),
	)
	defer sp.End()

	signer, err := n.keyMgr.GetActiveSigner(ctx, "")
	if err != nil {
		return "", err
	}

	issuer := n.deps.Cfg.GetIDP().OIDC.Issuer

	jwtID, err := n.tokenGen.GenerateToken("")
	if err != nil {
		return "", fmt.Errorf("failed to generate logout token id: %w", err)
	}

	claims := jwt.MapClaims{
		oidcClaimIssuer:   issuer,
		oidcClaimSubject:  userID,
		oidcClaimAudience: clientID,
		oidcClaimIssuedAt: time.Now().Unix(),
		"jti":             jwtID,
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}

	return signer.Sign(claims)
}

// ValidateToken parses and validates an access token (JWT or opaque).
func (n *NauthilusIDP) ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	ctx, sp := n.tracer.Start(ctx, "idp.validate_token")
	defer sp.End()

	// Heuristic: JWT tokens always contain dots. Opaque tokens (KSUIDs) do not.
	if !strings.Contains(tokenString, ".") {
		return n.opaqueTokenClaims(ctx, sp, tokenString, "idp.validate_token.opaque.redis_get", func(token *OpaqueAccessToken, session *OIDCSession) jwt.MapClaims {
			return token.ClaimsFromSession(session)
		}, nil)
	}

	// Fallback to JWT. Verify first so malformed input cannot force Redis denylist reads.
	verifyCtx, verifySpan := n.tracer.Start(ctx, "idp.validate_token.jwt.verify")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return n.resolveJWTPublicKey(verifyCtx, token)
	})
	if err != nil {
		verifySpan.RecordError(err)
	}

	verifySpan.End()

	if err != nil {
		sp.RecordError(err)

		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		denyCtx, denySpan := n.tracer.Start(ctx, "idp.validate_token.jwt.denylist")

		denied := n.storage.IsJWTAccessTokenDenied(denyCtx, tokenString)

		if denied {
			err := fmt.Errorf("access token has been revoked")
			denySpan.RecordError(err)
			denySpan.End()
			sp.RecordError(err)

			return nil, err
		}

		denySpan.End()

		if sub, ok := claims["sub"].(string); ok {
			sp.SetAttributes(attribute.String("sub", sub))
		}

		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// ValidateTokenForUserInfo validates an access token and returns IDTokenClaims suitable for the UserInfo endpoint.
// For opaque tokens it reads the IDTokenClaims from the stored session.
// For JWT tokens it falls back to standard JWT validation (claims are already embedded in the token).
func (n *NauthilusIDP) ValidateTokenForUserInfo(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	ctx, sp := n.tracer.Start(ctx, "idp.validate_token_for_userinfo")
	defer sp.End()

	// Heuristic: JWT tokens always contain dots. Opaque tokens (KSUIDs) do not.
	if !strings.Contains(tokenString, ".") {
		return n.opaqueTokenClaims(ctx, sp, tokenString, "idp.validate_token_for_userinfo.opaque.redis_get", func(token *OpaqueAccessToken, session *OIDCSession) jwt.MapClaims {
			return token.UserInfoClaimsFromSession(session)
		}, validateUserInfoSession)
	}

	// For JWT access tokens, fall back to standard validation.
	claims, err := n.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if !isAccessTokenClaims(claims) {
		return nil, fmt.Errorf("invalid token type for userinfo")
	}

	if !claimsIncludeScope(claims, definitions.ScopeOpenID) {
		return nil, fmt.Errorf("missing openid scope")
	}

	return claims, nil
}

// validateUserInfoSession requires the OIDC scope before releasing UserInfo claims.
func validateUserInfoSession(session *OIDCSession) error {
	if session == nil || !slices.Contains(session.Scopes, definitions.ScopeOpenID) {
		return fmt.Errorf("missing openid scope")
	}

	return nil
}

// isAccessTokenClaims reports whether JWT claims represent an API access token.
func isAccessTokenClaims(claims jwt.MapClaims) bool {
	tokenType, ok := claims[definitions.ClaimTokenType].(string)

	return ok && tokenType == definitions.TokenTypeAccessToken
}

// claimsIncludeScope reports whether a space-delimited scope claim contains a value.
func claimsIncludeScope(claims jwt.MapClaims, expectedScope string) bool {
	scopeValue, ok := claims[oidcClaimScope].(string)
	if !ok {
		return false
	}

	for scope := range strings.SplitSeq(scopeValue, " ") {
		if scope == expectedScope {
			return true
		}
	}

	return false
}

// opaqueTokenClaims loads an opaque access-token session and maps it to endpoint-specific claims.
func (n *NauthilusIDP) opaqueTokenClaims(
	ctx context.Context,
	parentSpan trace.Span,
	tokenString string,
	spanName string,
	buildClaims func(*OpaqueAccessToken, *OIDCSession) jwt.MapClaims,
	validateSession func(*OIDCSession) error,
) (jwt.MapClaims, error) {
	lookupCtx, lookupSpan := n.tracer.Start(ctx, spanName)

	session, err := n.storage.GetAccessTokenAuthoritative(lookupCtx, tokenString)
	if err != nil {
		lookupSpan.RecordError(err)
		parentSpan.RecordError(err)
	}

	lookupSpan.End()

	if err == nil && session != nil {
		if strings.HasPrefix(session.ClientID, dcr.ClientIDPrefix) {
			client, resolveErr := n.ResolveClient(ctx, session.ClientID)
			if resolveErr != nil {
				parentSpan.RecordError(resolveErr)

				return nil, fmt.Errorf("dynamic client is not active: %w", resolveErr)
			}

			if policyErr := n.validateDynamicSessionPolicy(client, session); policyErr != nil {
				parentSpan.RecordError(policyErr)

				return nil, policyErr
			}

			if lifetimeErr := validateDynamicAccessTokenLifetime(session, client.AccessTokenLifetime, time.Now()); lifetimeErr != nil {
				return nil, lifetimeErr
			}
		}

		if validateSession != nil {
			if err := validateSession(session); err != nil {
				parentSpan.RecordError(err)

				return nil, err
			}
		}

		token := NewOpaqueAccessToken(session, n.storage, n.tokenGen, 0)

		return buildClaims(token, session), nil
	}

	return nil, fmt.Errorf("invalid or expired opaque token")
}

// validateDynamicAccessTokenLifetime fail-closes missing, corrupt, narrowed, or expired lifetime metadata.
func validateDynamicAccessTokenLifetime(session *OIDCSession, currentLifetime time.Duration, now time.Time) error {
	if session == nil || session.AccessTokenIssuedAt.IsZero() || session.AccessTokenExpiresAt.IsZero() {
		return fmt.Errorf("dynamic access token has missing lifetime metadata")
	}

	currentExpiryCeiling := session.AccessTokenIssuedAt.Add(currentLifetime)
	if !session.AccessTokenExpiresAt.After(session.AccessTokenIssuedAt) || session.AccessTokenExpiresAt.After(currentExpiryCeiling) ||
		!now.Before(session.AccessTokenExpiresAt) {
		return fmt.Errorf("dynamic access token has invalid lifetime metadata")
	}

	return nil
}

// resolveJWTPublicKey returns the public key for verifying a JWT based on its algorithm and kid header.
func (n *NauthilusIDP) resolveJWTPublicKey(ctx context.Context, token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)

	_, sp := n.tracer.Start(ctx, "idp.validate_token.jwt.key_resolve",
		attribute.String("alg", fmt.Sprint(token.Header["alg"])),
		attribute.String("kid", kid),
	)

	defer sp.End()

	switch token.Method.(type) {
	case *jwt.SigningMethodRSA:
		key, err := n.resolveRSAPublicKey(ctx, kid)
		if err != nil {
			sp.RecordError(err)
		}

		return key, err
	case *jwt.SigningMethodEd25519:
		key, err := n.resolveEdDSAPublicKey(ctx, kid)
		if err != nil {
			sp.RecordError(err)
		}

		return key, err
	default:
		err := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		sp.RecordError(err)

		return nil, err
	}
}

// resolveRSAPublicKey finds the RSA public key matching the given kid.
func (n *NauthilusIDP) resolveRSAPublicKey(ctx context.Context, kid string) (any, error) {
	if kid != "" {
		key, err := n.keyMgr.GetRSAKeyByID(ctx, kid)
		if err != nil {
			return nil, err
		}

		return &key.PublicKey, nil
	}

	// Fallback: try the active key
	key, _, err := n.keyMgr.GetActiveKey(ctx)
	if err != nil {
		return nil, err
	}

	return &key.PublicKey, nil
}

// resolveEdDSAPublicKey finds the Ed25519 public key matching the given kid.
func (n *NauthilusIDP) resolveEdDSAPublicKey(ctx context.Context, kid string) (any, error) {
	if kid != "" {
		key, err := n.keyMgr.GetEdKeyByID(ctx, kid)
		if err != nil {
			return nil, err
		}

		return key.Public(), nil
	}

	// Fallback: try the active EdDSA signer
	signer, err := n.keyMgr.GetActiveSigner(ctx, "EdDSA")
	if err != nil {
		return nil, err
	}

	return signer.PublicKey(), nil
}

// PasswordAuthentication is the typed password-authentication result used by canonical browser flows.
type PasswordAuthentication struct {
	User          *backend.User
	MFAUser       *backend.User
	BackendRef    core.RemoteBackendRef
	MFABackendRef core.RemoteBackendRef
}

// AuthenticateWithBackend authenticates without reading or writing browser session state.
func (n *NauthilusIDP) AuthenticateWithBackend(
	ctx *gin.Context,
	username string,
	password string,
	oidcCID string,
	samlEntityID string,
	protocolContext core.IDPRequestContext,
) (PasswordAuthentication, error) {
	if n == nil || n.authApplication == nil {
		return PasswordAuthentication{}, fmt.Errorf("%w: idp auth application", core.ErrAuthApplicationDependencyMissing)
	}

	typedContext := protocolContext
	typedContext.RequestedScopes = append([]string(nil), protocolContext.RequestedScopes...)

	entryPoint, err := idpAuthenticationEntry(oidcCID, samlEntityID, typedContext)
	if err != nil {
		return PasswordAuthentication{}, err
	}

	outcome, _, err := n.authApplication.authenticate(ctx, idpAuthApplicationRequest{
		protocolContext: typedContext,
		username:        username,
		password:        password,
		oidcClientID:    oidcCID,
		samlEntityID:    samlEntityID,
		entryPoint:      entryPoint,
	})
	if err != nil {
		return PasswordAuthentication{}, err
	}

	result, err := passwordAuthenticationFromOutcome(outcome)
	if err == nil {
		err = authFailureFromOutcome(outcome)
	}

	if err != nil && n.IsDelayedResponse(oidcCID, samlEntityID) &&
		delayedPasswordFailureEligible(err) {
		if hydrated, lookupErr := n.lookupPasswordIdentity(
			ctx, username, oidcCID, samlEntityID, core.AuthnEntryIDPDelayedIdentity, typedContext,
		); lookupErr == nil {
			result = hydrated
		} else if n.deps.Logger != nil {
			n.deps.Logger.Warn(
				"Delayed password identity lookup failed",
				definitions.LogKeyError, lookupErr,
			)
		}
	}

	if result.User != nil {
		bound, bindErr := n.bindPasswordMFAIdentity(
			ctx, username, oidcCID, samlEntityID, typedContext, result,
		)
		if bindErr != nil {
			if err == nil {
				return PasswordAuthentication{}, bindErr
			}

			if n.deps.Logger != nil {
				n.deps.Logger.Warn(
					"Delayed password MFA identity lookup failed",
					definitions.LogKeyError, bindErr,
				)
			}
		} else {
			result = bound
		}
	}

	return result, err
}

// passwordAuthenticationFromOutcome projects admitted identity and backend ownership from an application outcome.
func passwordAuthenticationFromOutcome(outcome *core.AuthOutcome) (PasswordAuthentication, error) {
	if outcome == nil {
		return PasswordAuthentication{}, core.ErrAuthOutcomeMissing
	}

	result := PasswordAuthentication{
		User:       backendUserFromOutcomeIdentity(outcome),
		BackendRef: outcome.RemoteBackendRef,
	}
	if outcome.Decision == core.AuthDecisionOK && result.User == nil {
		return PasswordAuthentication{}, fmt.Errorf("successful password authentication returned no identity")
	}

	return result, nil
}

func delayedPasswordFailureEligible(err error) bool {
	var failure *AuthFailureError

	return errors.As(err, &failure) && failure.Status.DelayedResponseEligible
}

// bindPasswordMFAIdentity separates the asserted target from the account proving MFA.
func (n *NauthilusIDP) bindPasswordMFAIdentity(
	ctx *gin.Context,
	username string,
	oidcCID string,
	samlEntityID string,
	protocolContext core.IDPRequestContext,
	result PasswordAuthentication,
) (PasswordAuthentication, error) {
	if result.User == nil {
		return PasswordAuthentication{}, fmt.Errorf("password MFA identity: target user is missing")
	}

	result.MFAUser = result.User
	result.MFABackendRef = result.BackendRef

	server := n.deps.Cfg.GetServer()
	if server == nil || !server.GetMasterUser().IsEnabled() {
		return result, nil
	}

	target, master, masterLogin := config.ParseMasterUserLogin(
		username, server.GetMasterUser().GetUserFormat(),
	)
	if !masterLogin {
		return result, nil
	}

	if target != result.User.Name {
		return PasswordAuthentication{}, sessionstate.ErrBindingMismatch
	}

	factor, err := n.lookupPasswordIdentity(
		ctx, master, oidcCID, samlEntityID, core.AuthnEntryIDPMasterFactor, protocolContext,
	)
	if err != nil {
		return PasswordAuthentication{}, err
	}

	if factor.User == nil || factor.User.Name != master || factor.User.ID == "" || factor.BackendRef.IsZero() {
		return PasswordAuthentication{}, sessionstate.ErrBindingMismatch
	}

	result.MFAUser = factor.User
	result.MFABackendRef = factor.BackendRef

	return result, nil
}

// lookupPasswordIdentity resolves one explicit account without password verification or browser state.
func (n *NauthilusIDP) lookupPasswordIdentity(
	ctx *gin.Context,
	username string,
	oidcCID string,
	samlEntityID string,
	entryPoint core.AuthnEntryPoint,
	protocolContext core.IDPRequestContext,
) (PasswordAuthentication, error) {
	if n == nil || n.authApplication == nil || ctx == nil || ctx.Request == nil {
		return PasswordAuthentication{}, fmt.Errorf("password identity lookup unavailable")
	}

	attributeRequest, err := n.delayedPasswordIdentityAttributes(ctx.Request.Context(), oidcCID, samlEntityID, protocolContext)
	if err != nil {
		return PasswordAuthentication{}, err
	}

	typedContext := protocolContext
	typedContext.RequestedScopes = append([]string(nil), protocolContext.RequestedScopes...)

	outcome, _, err := n.authApplication.lookupIdentity(ctx, idpAuthApplicationRequest{
		attributeRequest: attributeRequest,
		protocolContext:  typedContext,
		username:         username,
		oidcClientID:     oidcCID,
		samlEntityID:     samlEntityID,
		entryPoint:       entryPoint,
	})
	if err != nil {
		return PasswordAuthentication{}, err
	}

	if err := authFailureFromOutcome(outcome); err != nil {
		return PasswordAuthentication{}, err
	}

	return passwordAuthenticationFromOutcome(outcome)
}

func (n *NauthilusIDP) delayedPasswordIdentityAttributes(
	ctx context.Context,
	oidcCID string,
	samlEntityID string,
	protocolContext core.IDPRequestContext,
) (*core.IdentityAttributeRequest, error) {
	if oidcCID != "" {
		client, err := n.ResolveClient(ctx, oidcCID)
		if err != nil {
			return nil, err
		}

		effectiveScopes := n.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)

		return core.NewOIDCIdentityAttributeRequest(
			client, protocolContext.RequestedScopes, effectiveScopes,
		), nil
	}

	if samlEntityID != "" {
		serviceProvider, ok := n.FindSAMLServiceProvider(samlEntityID)
		if !ok {
			return nil, fmt.Errorf("delayed password SAML service provider not found")
		}

		return core.NewSAMLIdentityAttributeRequest(serviceProvider), nil
	}

	return nil, fmt.Errorf("delayed password protocol binding is missing")
}

// GetUserByUsernameForOIDCClaims retrieves user data needed for OIDC claim materialization.
func (n *NauthilusIDP) GetUserByUsernameForOIDCClaims(
	ctx *gin.Context,
	username string,
	client *config.OIDCClient,
	scopes []string,
) (*backend.User, error) {
	if client == nil {
		return nil, fmt.Errorf("OIDC user lookup unavailable: client is nil")
	}

	return n.GetUserByUsernameForOIDCClaimsCanonical(
		ctx,
		username,
		client,
		scopes,
		core.RemoteBackendRef{},
		core.IDPRequestContext{
			GrantType:       definitions.OIDCFlowDeviceCode,
			RequestedScopes: append([]string(nil), scopes...),
		},
	)
}

// GetUserByUsernameForOIDCClaimsCanonical loads OIDC claim material through only typed request state.
func (n *NauthilusIDP) GetUserByUsernameForOIDCClaimsCanonical(
	ctx *gin.Context,
	username string,
	client *config.OIDCClient,
	scopes []string,
	backendRef core.RemoteBackendRef,
	protocolContext core.IDPRequestContext,
) (*backend.User, error) {
	if n == nil || ctx == nil || ctx.Request == nil || client == nil {
		return nil, fmt.Errorf("canonical OIDC user lookup unavailable")
	}

	effectiveScopes := n.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)
	attributeRequest := core.NewOIDCIdentityAttributeRequest(client, scopes, effectiveScopes)
	typedContext := protocolContext
	typedContext.RequestedScopes = append([]string(nil), protocolContext.RequestedScopes...)

	entryPoint, err := idpOIDCLookupEntry(typedContext)
	if err != nil {
		return nil, err
	}

	outcome, _, err := n.authApplication.lookupIdentity(ctx, idpAuthApplicationRequest{
		attributeRequest: attributeRequest,
		protocolContext:  typedContext,
		backendRef:       backendRef,
		username:         username,
		oidcClientID:     client.ClientID,
		entryPoint:       entryPoint,
	})
	if err != nil {
		return nil, err
	}

	if err := authFailureFromOutcome(outcome); err != nil {
		return nil, err
	}

	return backendUserFromAuthOutcome(outcome)
}

// GetUserByUsernameForSAMLCanonical loads SAML attributes through only typed request state.
func (n *NauthilusIDP) GetUserByUsernameForSAMLCanonical(
	ctx *gin.Context,
	username string,
	spConfig *config.SAML2ServiceProvider,
	backendRef core.RemoteBackendRef,
	protocolContext core.IDPRequestContext,
) (*backend.User, error) {
	if n == nil || ctx == nil || ctx.Request == nil || spConfig == nil {
		return nil, fmt.Errorf("canonical SAML user lookup unavailable")
	}

	attributeRequest := core.NewSAMLIdentityAttributeRequest(spConfig)
	typedContext := protocolContext
	typedContext.RequestedScopes = append([]string(nil), protocolContext.RequestedScopes...)

	outcome, _, err := n.authApplication.lookupIdentity(ctx, idpAuthApplicationRequest{
		attributeRequest: attributeRequest,
		protocolContext:  typedContext,
		backendRef:       backendRef,
		username:         username,
		samlEntityID:     spConfig.EntityID,
		entryPoint:       core.AuthnEntryIDPSAML,
	})
	if err != nil {
		return nil, err
	}

	if err := authFailureFromOutcome(outcome); err != nil {
		return nil, err
	}

	return backendUserFromAuthOutcome(outcome)
}

// GetClaims retrieves user attributes and maps them to OIDC/SAML claims for a specific client.

// GetClaims provides the exported GetClaims method.
func (n *NauthilusIDP) GetClaims(ctx *gin.Context, user *backend.User, client any, scopes []string) (map[string]any, map[string]any, error) {
	idTokenClaims := map[string]any{
		oidcClaimSubject:     user.ID,
		"name":               user.DisplayName,
		"preferred_username": user.Name,
	}
	accessTokenClaims := make(map[string]any)

	// Map attributes from backend using claim mappings when client is OIDCClient.
	if oidcClient, ok := client.(*config.OIDCClient); ok {
		effectiveCustomScopes := n.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(oidcClient)

		// We need an AuthState to use FillIDTokenClaims
		// We can create a lightweight AuthState just for mapping
		authRaw := core.NewAuthStateFromContextWithDeps(ctx, n.deps.Auth())

		auth, ok := authRaw.(*core.AuthState)
		if !ok || auth == nil {
			return nil, nil, fmt.Errorf("failed to create AuthState for mapping")
		}

		if auth.Runtime.GUID == "" {
			auth.Runtime.GUID = ctx.GetString(definitions.CtxGUIDKey)
		}

		auth.ReplaceAllAttributes(user.Attributes)
		auth.SetResolvedGroups(user.Groups, user.GroupDistinguishedNames)

		auth.FillIDTokenClaims(&oidcClient.IDTokenClaims, idTokenClaims, scopes, effectiveCustomScopes)
		auth.FillAccessTokenClaims(&oidcClient.AccessTokenClaims, accessTokenClaims, scopes, effectiveCustomScopes)
	}

	return idTokenClaims, accessTokenClaims, nil
}
