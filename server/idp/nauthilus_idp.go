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
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp/oidckeys"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// NauthilusIDP implements the IdentityProvider interface using Nauthilus core.
type NauthilusIDP struct {
	deps     *deps.Deps
	storage  *RedisTokenStorage
	tracer   monittrace.Tracer
	keyMgr   *oidckeys.Manager
	tokenGen TokenGenerator
}

var (
	// ErrInvalidRefreshToken indicates the submitted refresh token was unknown or expired.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrRefreshTokenClientMismatch indicates the refresh token was not issued to the requesting client.
	ErrRefreshTokenClientMismatch = errors.New("refresh token client mismatch")
)

// NewNauthilusIDP creates a new instance of NauthilusIDP.
func NewNauthilusIDP(d *deps.Deps) *NauthilusIDP {
	return &NauthilusIDP{
		deps:     d,
		storage:  NewRedisTokenStorageWithConfig(d.Redis, d.Cfg.GetServer().GetRedis().GetPrefix(), d.Cfg),
		tracer:   monittrace.New("nauthilus/idp"),
		keyMgr:   oidckeys.NewManager(d),
		tokenGen: NewDefaultTokenGenerator(),
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
	for i := range clients {
		if clients[i].ClientID == clientID {
			return &clients[i], true
		}
	}

	return nil, false
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
	client, ok := n.FindClient(session.ClientID)
	if !ok {
		return "", "", "", 0, fmt.Errorf("client not found")
	}

	return n.issueTokensForClient(ctx, client, session, "")
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
		refreshToken = n.tokenGen.GenerateToken(definitions.OIDCTokenPrefixRefreshToken)
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

	if err := ValidateClientCredentialsScopes(scopes); err != nil {
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

	// Build session for client credentials (no user, client is the subject)
	session := &OIDCSession{
		ClientID:            clientID,
		UserID:              clientID,
		Scopes:              scopes,
		AuthTime:            time.Now(),
		AccessTokenAudience: clientCredentialsAccessTokenAudience(scopes),
		AccessTokenClaims:   make(map[string]any),
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

	session, err := n.storage.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, "", "", "", 0, fmt.Errorf("%w", ErrInvalidRefreshToken)
	}

	if session.ClientID != clientID {
		return nil, "", "", "", 0, fmt.Errorf("%w", ErrRefreshTokenClientMismatch)
	}

	client, ok := n.FindClient(clientID)
	if !ok {
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

	claims := jwt.MapClaims{
		oidcClaimIssuer:   issuer,
		oidcClaimSubject:  userID,
		oidcClaimAudience: clientID,
		oidcClaimIssuedAt: time.Now().Unix(),
		"jti":             n.tokenGen.GenerateToken(""),
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

	session, err := n.storage.GetAccessToken(lookupCtx, tokenString)
	if err != nil {
		lookupSpan.RecordError(err)
		parentSpan.RecordError(err)
	}

	lookupSpan.End()

	if err == nil && session != nil {
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

// Authenticate performs user authentication using AuthState.
func (n *NauthilusIDP) Authenticate(ctx *gin.Context, username, password string, oidcCID string, samlEntityID string) (*backend.User, error) {
	_, sp := n.tracer.Start(ctx.Request.Context(), "idp.authenticate",
		attribute.String("username", username),
		attribute.String("oidc_cid", oidcCID),
		attribute.String("saml_entity_id", samlEntityID),
	)
	defer sp.End()

	auth, err := n.newPasswordAuthState(ctx, username, password, oidcCID, samlEntityID, sp)
	if err != nil {
		return nil, err
	}

	if err := n.rejectBruteForceAuthentication(ctx, auth, sp); err != nil {
		return nil, err
	}

	if err := n.rejectEnvironmentAuthentication(ctx, auth, sp); err != nil {
		return nil, err
	}

	if err := n.rejectPasswordAuthentication(ctx, auth, sp); err != nil {
		return nil, err
	}

	n.storeAuthenticationSession(ctx, auth)

	return n.userFromAuthState(auth)
}

// newPasswordAuthState creates and configures AuthState for password authentication.
func (n *NauthilusIDP) newPasswordAuthState(
	ctx *gin.Context,
	username string,
	password string,
	oidcCID string,
	samlEntityID string,
	sp trace.Span,
) (*core.AuthState, error) {
	authRaw := core.NewAuthStateFromContextWithDeps(ctx, n.deps.Auth())

	auth, ok := authRaw.(*core.AuthState)
	if !ok || auth == nil {
		err := fmt.Errorf("failed to create AuthState")
		sp.RecordError(err)

		return nil, err
	}

	configurePasswordAuthState(auth, username, password, oidcCID, samlEntityID)
	auth.FinishSetup(ctx)

	return auth, nil
}

// configurePasswordAuthState applies caller credentials and protocol metadata.
func configurePasswordAuthState(auth *core.AuthState, username string, password string, oidcCID string, samlEntityID string) {
	auth.SetUsername(username)
	auth.SetPassword(secret.New(password))
	auth.SetMethod(definitions.AuthMethodPassword)
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)

	if oidcCID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoOIDC))
	} else if samlEntityID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoSAML))
	} else {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	}
}

// rejectBruteForceAuthentication applies pre-auth brute-force protection decisions.
func (n *NauthilusIDP) rejectBruteForceAuthentication(ctx *gin.Context, auth *core.AuthState, sp trace.Span) error {
	if !auth.CheckBruteForce(ctx) {
		return nil
	}

	if auth.ApplyConfiguredPreAuthDecision(ctx) {
		return n.finishAuthenticationFailure(ctx, auth, sp, definitions.AuthResultFail, bruteForceAuthenticationError(), false)
	}

	if auth.ApplyConfiguredPreAuthControl(ctx) || auth.HasConfiguredPreAuthPolicyAuthority(ctx) {
		return nil
	}

	if auth.ApplyDefaultPreAuthDecision(ctx) {
		return n.finishAuthenticationFailure(ctx, auth, sp, definitions.AuthResultFail, bruteForceAuthenticationError(), false)
	}

	auth.UpdateBruteForceBucketsCounter(ctx)

	return n.finishAuthenticationFailure(ctx, auth, sp, definitions.AuthResultFail, bruteForceAuthenticationError(), true)
}

// rejectEnvironmentAuthentication fails authentication when pre-auth environment checks reject it.
func (n *NauthilusIDP) rejectEnvironmentAuthentication(ctx *gin.Context, auth *core.AuthState, sp trace.Span) error {
	res := auth.HandleEnvironment(ctx)
	if res == definitions.AuthResultOK || res == definitions.AuthResultUnset {
		return nil
	}

	return n.finishAuthenticationFailure(ctx, auth, sp, res, fmt.Errorf("authentication failed with pre-auth result: %d", res), true)
}

// rejectPasswordAuthentication fails authentication when password verification rejects it.
func (n *NauthilusIDP) rejectPasswordAuthentication(ctx *gin.Context, auth *core.AuthState, sp trace.Span) error {
	result := auth.HandlePassword(ctx)

	auth.FinishLogging(ctx, result)

	if result == definitions.AuthResultOK {
		return nil
	}

	err := fmt.Errorf("authentication failed with result: %d", result)
	sp.RecordError(err)

	return n.authFailureError(ctx, auth, err)
}

// finishAuthenticationFailure records a failed authentication with optional AuthFail side effects.
func (n *NauthilusIDP) finishAuthenticationFailure(
	ctx *gin.Context,
	auth *core.AuthState,
	sp trace.Span,
	result definitions.AuthResult,
	err error,
	markAuthFail bool,
) error {
	if markAuthFail {
		auth.AuthFail(ctx)
	}

	auth.FinishLogging(ctx, result)
	sp.RecordError(err)

	return n.authFailureError(ctx, auth, err)
}

// storeAuthenticationSession persists backend affinity data for the browser session.
func (n *NauthilusIDP) storeAuthenticationSession(ctx *gin.Context, auth *core.AuthState) {
	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Set(definitions.SessionKeyUserBackend, uint8(auth.GetSourcePassDBBackend()))
		mgr.Set(definitions.SessionKeyUserBackendName, auth.GetUsedPassDBBackendName())
		core.StoreRemoteBackendRef(mgr, auth.Runtime.RemoteBackendRef)
	}
}

// bruteForceAuthenticationError returns the shared brute-force authentication failure.
func bruteForceAuthenticationError() error {
	return fmt.Errorf("authentication failed due to brute force protection")
}

// GetUserByUsername retrieves user details and attributes without performing password authentication.
func (n *NauthilusIDP) GetUserByUsername(ctx *gin.Context, username string, oidcCID string, samlEntityID string) (*backend.User, error) {
	return n.getUserByUsername(ctx, username, oidcCID, samlEntityID, nil)
}

// GetUserByUsernameForOIDCClaims retrieves user data needed for OIDC claim materialization.
func (n *NauthilusIDP) GetUserByUsernameForOIDCClaims(
	ctx *gin.Context,
	username string,
	client *config.OIDCClient,
	scopes []string,
) (*backend.User, error) {
	if client == nil {
		return n.getUserByUsername(ctx, username, "", "", nil)
	}

	effectiveScopes := n.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)
	request := core.NewOIDCIdentityAttributeRequest(client, scopes, effectiveScopes)

	return n.getUserByUsername(ctx, username, client.ClientID, "", request)
}

// GetUserByUsernameForSAML retrieves user data needed for SAML attribute materialization.
func (n *NauthilusIDP) GetUserByUsernameForSAML(
	ctx *gin.Context,
	username string,
	sp *config.SAML2ServiceProvider,
) (*backend.User, error) {
	if sp == nil {
		return n.getUserByUsername(ctx, username, "", "", nil)
	}

	request := core.NewSAMLIdentityAttributeRequest(sp)

	return n.getUserByUsername(ctx, username, "", sp.EntityID, request)
}

func (n *NauthilusIDP) getUserByUsername(
	ctx *gin.Context,
	username string,
	oidcCID string,
	samlEntityID string,
	attributeRequest *core.IdentityAttributeRequest,
) (*backend.User, error) {
	_, sp := n.tracer.Start(ctx.Request.Context(), "idp.get_user_by_username",
		attribute.String("username", username),
		attribute.String("oidc_cid", oidcCID),
		attribute.String("saml_entity_id", samlEntityID),
	)
	defer sp.End()

	authRaw := core.NewAuthStateFromContextWithDeps(ctx, n.deps.Auth())
	auth, ok := authRaw.(*core.AuthState)

	if !ok || auth == nil {
		err := fmt.Errorf("failed to create AuthState")
		sp.RecordError(err)

		return nil, err
	}

	if ref, ok := core.RemoteBackendRefFromSession(cookie.GetManager(ctx)); ok {
		auth.Runtime.RemoteBackendRef = ref
	}

	prepareUserLookupAuthState(ctx, auth, username, oidcCID, samlEntityID, attributeRequest)

	// We use HandlePassword with NoAuth=true which should skip password check but load attributes
	// depending on how backends handle NoAuth.
	// Alternatively, we can use a more direct way if AuthState supports it.
	result := auth.HandlePassword(ctx)
	if result != definitions.AuthResultOK {
		err := fmt.Errorf("failed to load user: %d", result)
		sp.RecordError(err)

		return nil, err
	}

	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Set(definitions.SessionKeyUserBackend, uint8(auth.GetSourcePassDBBackend()))
		mgr.Set(definitions.SessionKeyUserBackendName, auth.GetUsedPassDBBackendName())
		core.StoreRemoteBackendRef(mgr, auth.Runtime.RemoteBackendRef)
	}

	return n.userFromAuthState(auth)
}

// prepareUserLookupAuthState applies the requested identity lookup inputs before no-auth loading.
func prepareUserLookupAuthState(
	ctx *gin.Context,
	auth *core.AuthState,
	username string,
	oidcCID string,
	samlEntityID string,
	attributeRequest *core.IdentityAttributeRequest,
) {
	auth.FinishSetup(ctx)
	auth.SetUsername(username)
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)
	auth.Runtime.IdentityAttributeRequest = attributeRequest.Clone()

	if oidcCID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoOIDC))
	} else if samlEntityID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoSAML))
	} else {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	}

	auth.SetNoAuth(true)
}

func (n *NauthilusIDP) userFromAuthState(auth *core.AuthState) (*backend.User, error) {
	accountName, ok := auth.GetAccountOk()
	if !ok {
		return nil, fmt.Errorf("failed to get account name")
	}

	displayName := auth.GetDisplayName()
	uniqueID := auth.GetUniqueUserID()

	user := backend.NewUser(accountName, displayName, uniqueID)
	user.Attributes = auth.GetAttributes()
	user.Groups = auth.GetGroups()
	user.GroupDistinguishedNames = auth.GetGroupDistinguishedNames()
	user.TOTPSecretField = auth.GetTOTPSecretField()
	user.TOTPRecoveryField = auth.GetTOTPRecoveryField()

	return user, nil
}

func (n *NauthilusIDP) authFailureError(ctx *gin.Context, auth *core.AuthState, err error) error {
	if auth == nil {
		return err
	}

	status := AuthFailureStatus{
		StatusMessage:    auth.Runtime.StatusMessage,
		I18NKey:          auth.Runtime.StatusMessageI18NKey,
		ResponseLanguage: auth.Runtime.ResponseLanguage,
	}

	if _, ok := auth.ConfiguredPolicyTerminalDecision(ctx); ok {
		status.PolicyTerminal = true
		status.DelayedResponseEligible = auth.ConfiguredPolicyAllowsIDPDelayedResponse(ctx)
	} else if status.HasI18NStatus() {
		status.PolicyTerminal = true
	}

	return NewAuthFailureError(err, status)
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
