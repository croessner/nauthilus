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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp/oidckeys"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
)

// NauthilusIdP implements the IdentityProvider interface using Nauthilus core.
type NauthilusIdP struct {
	deps     *deps.Deps
	storage  *RedisTokenStorage
	tracer   monittrace.Tracer
	keyMgr   *oidckeys.Manager
	tokenGen TokenGenerator
}

// NewNauthilusIdP creates a new instance of NauthilusIdP.
func NewNauthilusIdP(d *deps.Deps) *NauthilusIdP {
	return &NauthilusIdP{
		deps:     d,
		storage:  NewRedisTokenStorage(d.Redis, d.Cfg.GetServer().GetRedis().GetPrefix()),
		tracer:   monittrace.New("nauthilus/idp"),
		keyMgr:   oidckeys.NewManager(d),
		tokenGen: NewDefaultTokenGenerator(),
	}
}

// GetKeyManager returns the OIDC key manager.
func (n *NauthilusIdP) GetKeyManager() *oidckeys.Manager {
	return n.keyMgr
}

// FilterScopes filters the requested scopes against the allowed scopes for the client.
func (n *NauthilusIdP) FilterScopes(client *config.OIDCClient, requestedScopes []string) []string {
	allowed := client.GetAllowedScopes()
	allowedMap := make(map[string]struct{}, len(allowed))

	for _, s := range allowed {
		allowedMap[s] = struct{}{}
	}

	var filtered []string

	for _, rs := range requestedScopes {
		if rs == "" {
			continue
		}

		if _, ok := allowedMap[rs]; ok {
			filtered = append(filtered, rs)
		}
	}

	return filtered
}

// FindClient returns an OIDC client by its ID.
func (n *NauthilusIdP) FindClient(clientID string) (*config.OIDCClient, bool) {
	clients := n.deps.Cfg.GetIdP().OIDC.Clients
	for i := range clients {
		if clients[i].ClientID == clientID {
			return &clients[i], true
		}
	}

	return nil, false
}

// FindSAMLServiceProvider returns a SAML service provider by its entity ID.
func (n *NauthilusIdP) FindSAMLServiceProvider(entityID string) (*config.SAML2ServiceProvider, bool) {
	for _, sp := range n.deps.Cfg.GetIdP().SAML2.ServiceProviders {
		if sp.EntityID == entityID {
			return &sp, true
		}
	}

	return nil, false
}

// IsDelayedResponse returns true if delayed response is enabled for the given client.
func (n *NauthilusIdP) IsDelayedResponse(clientID string, samlEntityID string) bool {
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
func (n *NauthilusIdP) ValidateRedirectURI(client *config.OIDCClient, redirectURI string) bool {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}

	return false
}

// ValidatePostLogoutRedirectURI checks if the given post-logout redirect URI is valid for the client.
func (n *NauthilusIdP) ValidatePostLogoutRedirectURI(client *config.OIDCClient, redirectURI string) bool {
	if redirectURI == "" {
		return true
	}

	for _, uri := range client.PostLogoutRedirectURIs {
		if uri == redirectURI {
			return true
		}
	}

	return false
}

// IssueTokens generates tokens for the given OIDC session.
// Per OIDC Core 1.0 §3.1.2.1, an ID token is only issued when the "openid" scope is present.
// Without "openid", this behaves as a pure OAuth 2.0 token response (access_token only).
func (n *NauthilusIdP) IssueTokens(ctx context.Context, session *OIDCSession) (string, string, string, time.Duration, error) {
	_, sp := n.tracer.Start(ctx, "idp.issue_tokens",
		attribute.String("client_id", session.ClientID),
		attribute.String("user_id", session.UserID),
	)
	defer sp.End()

	client, ok := n.FindClient(session.ClientID)
	if !ok {
		return "", "", "", 0, fmt.Errorf("client not found")
	}

	accessTokenLifetime := client.AccessTokenLifetime
	if accessTokenLifetime == 0 {
		accessTokenLifetime = n.deps.Cfg.GetIdP().OIDC.GetDefaultAccessTokenLifetime()
	}

	issuer := n.deps.Cfg.GetIdP().OIDC.Issuer
	key, kid, err := n.keyMgr.GetActiveKey(ctx)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("failed to get active signing key: %w", err)
	}

	now := time.Now()

	// Per OIDC Core 1.0 §3.1.2.1: ID token is only issued when the "openid" scope is requested.
	var idTokenString string

	if slices.Contains(session.Scopes, definitions.ScopeOpenId) {
		idClaims := jwt.MapClaims{
			"iss":       issuer,
			"sub":       session.UserID,
			"aud":       session.ClientID,
			"exp":       now.Add(accessTokenLifetime).Unix(),
			"iat":       now.Unix(),
			"auth_time": session.AuthTime.Unix(),
		}

		if session.Nonce != "" {
			idClaims["nonce"] = session.Nonce
		}

		// Add mapped claims from session
		for k, v := range session.IdTokenClaims {
			idClaims[k] = v
		}

		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
		idToken.Header["kid"] = kid

		idTokenString, err = idToken.SignedString(key)
		if err != nil {
			sp.RecordError(err)

			return "", "", "", 0, fmt.Errorf("failed to sign ID token: %w", err)
		}
	}

	// Access Token
	tokenIssuer := NewTokenIssuer(issuer, key, kid, session, n.storage, n.tokenGen)
	accessTokenType := client.GetAccessTokenType(n.deps.Cfg.GetIdP().OIDC.GetAccessTokenType())

	var accessTokenString string

	if accessTokenType == "opaque" {
		accessTokenString, _, err = tokenIssuer.IssueOpaque(ctx, accessTokenLifetime)
	} else {
		accessTokenString, _, err = tokenIssuer.IssueJWT(ctx, accessTokenLifetime)
	}

	if err != nil {
		sp.RecordError(err)

		return "", "", "", 0, err
	}

	refreshTokenString := ""
	hasOfflineAccess := slices.Contains(session.Scopes, definitions.ScopeOfflineAccess)

	if hasOfflineAccess {
		refreshTokenString = n.tokenGen.GenerateToken(definitions.OIDCTokenPrefixRefreshToken)
		refreshTokenLifetime := client.RefreshTokenLifetime

		if refreshTokenLifetime == 0 {
			refreshTokenLifetime = n.deps.Cfg.GetIdP().OIDC.GetDefaultRefreshTokenLifetime()
		}

		// Link the access token to the refresh token session so it can be
		// invalidated during token rotation (RFC 6749 best practice).
		session.AccessToken = accessTokenString

		err = n.storage.StoreRefreshToken(ctx, refreshTokenString, session, refreshTokenLifetime)
		if err != nil {
			sp.RecordError(err)

			return "", "", "", 0, fmt.Errorf("failed to store refresh token: %w", err)
		}
	}

	return idTokenString, accessTokenString, refreshTokenString, accessTokenLifetime, nil
}

// IssueClientCredentialsToken generates an access token for the Client Credentials Grant.
// Per RFC 6749 §4.4, only an access token is returned (no id_token, no refresh_token).
func (n *NauthilusIdP) IssueClientCredentialsToken(ctx context.Context, clientID string, scopes []string) (string, time.Duration, error) {
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

	accessTokenLifetime := client.AccessTokenLifetime
	if accessTokenLifetime == 0 {
		accessTokenLifetime = n.deps.Cfg.GetIdP().OIDC.GetDefaultAccessTokenLifetime()
	}

	issuer := n.deps.Cfg.GetIdP().OIDC.Issuer
	key, kid, err := n.keyMgr.GetActiveKey(ctx)
	if err != nil {
		sp.RecordError(err)

		return "", 0, fmt.Errorf("failed to get active signing key: %w", err)
	}

	// Build session for client credentials (no user, client is the subject)
	session := &OIDCSession{
		ClientID:          clientID,
		UserID:            clientID,
		Scopes:            scopes,
		AuthTime:          time.Now(),
		AccessTokenClaims: make(map[string]any),
	}

	// Access Token
	tokenIssuer := NewTokenIssuer(issuer, key, kid, session, n.storage, n.tokenGen)
	accessTokenType := client.GetAccessTokenType(n.deps.Cfg.GetIdP().OIDC.GetAccessTokenType())

	var accessTokenString string

	if accessTokenType == "opaque" {
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
func (n *NauthilusIdP) ExchangeRefreshToken(ctx context.Context, refreshToken string, clientID string) (string, string, string, time.Duration, error) {
	_, sp := n.tracer.Start(ctx, "idp.exchange_refresh_token",
		attribute.String("client_id", clientID),
	)
	defer sp.End()

	session, err := n.storage.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("invalid refresh token")
	}

	if session.ClientID != clientID {
		return "", "", "", 0, fmt.Errorf("client mismatch")
	}

	// Rotation: invalidate old access token and delete old refresh token
	// (RFC 6749 best practice for token rotation).
	n.invalidateOldAccessToken(ctx, session, clientID)

	_ = n.storage.DeleteRefreshToken(ctx, refreshToken)

	// Clear the old access token reference before issuing new tokens.
	session.AccessToken = ""

	return n.IssueTokens(ctx, session)
}

// invalidateOldAccessToken removes the previous access token that was linked
// to the refresh token session. For opaque tokens it deletes the Redis entry;
// for JWT tokens it adds the token to a denylist with the remaining lifetime.
func (n *NauthilusIdP) invalidateOldAccessToken(ctx context.Context, session *OIDCSession, clientID string) {
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
		ttl = n.deps.Cfg.GetIdP().OIDC.GetDefaultAccessTokenLifetime()
	}

	_ = n.storage.DenyJWTAccessToken(ctx, oldAccessToken, ttl)
}

// IssueLogoutToken generates a logout token for the given client and user.
func (n *NauthilusIdP) IssueLogoutToken(ctx context.Context, clientID string, userID string) (string, error) {
	_, sp := n.tracer.Start(ctx, "idp.issue_logout_token",
		attribute.String("client_id", clientID),
		attribute.String("user_id", userID),
	)
	defer sp.End()

	key, kid, err := n.keyMgr.GetActiveKey(ctx)
	if err != nil {
		return "", err
	}

	issuer := n.deps.Cfg.GetIdP().OIDC.Issuer

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": userID,
		"aud": clientID,
		"iat": time.Now().Unix(),
		"jti": n.tokenGen.GenerateToken(""),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = kid

	return token.SignedString(key)
}

// ValidateToken parses and validates an access token (JWT or opaque).
func (n *NauthilusIdP) ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	_, sp := n.tracer.Start(ctx, "idp.validate_token")
	defer sp.End()

	// Heuristic: JWT tokens always contain dots. Opaque tokens (KSUIDs) do not.
	if !strings.Contains(tokenString, ".") {
		session, err := n.storage.GetAccessToken(ctx, tokenString)
		if err == nil && session != nil {
			token := NewOpaqueAccessToken(session, n.storage, n.tokenGen, 0)

			return token.Validate(ctx, tokenString)
		}

		return nil, fmt.Errorf("invalid or expired opaque token")
	}

	// Check JWT denylist before validation.
	if n.storage.IsJWTAccessTokenDenied(ctx, tokenString) {
		return nil, fmt.Errorf("access token has been revoked")
	}

	// Fallback to JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, _ := token.Header["kid"].(string)
		allKeys, err := n.keyMgr.GetAllKeys(ctx)
		if err != nil {
			return nil, err
		}

		if kid != "" {
			if key, ok := allKeys[kid]; ok {
				return &key.PublicKey, nil
			}

			return nil, fmt.Errorf("key with kid %s not found", kid)
		}

		// Fallback: if no kid, try the active key or all keys
		key, _, err := n.keyMgr.GetActiveKey(ctx)
		if err != nil {
			return nil, err
		}

		return &key.PublicKey, nil
	})

	if err != nil {
		sp.RecordError(err)

		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		sp.SetAttributes(attribute.String("sub", claims["sub"].(string)))

		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// Authenticate performs user authentication using AuthState.
func (n *NauthilusIdP) Authenticate(ctx *gin.Context, username, password string, oidcCID string, samlEntityID string) (*backend.User, error) {
	_, sp := n.tracer.Start(ctx.Request.Context(), "idp.authenticate",
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

	auth.SetUsername(username)
	auth.SetPassword(password)
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)

	if oidcCID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoOIDC))
	} else if samlEntityID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoSAML))
	} else {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	}

	auth.FinishSetup(ctx)

	if auth.CheckBruteForce(ctx) {
		auth.UpdateBruteForceBucketsCounter(ctx)
		auth.AuthFail(ctx)
		auth.FinishLogging(ctx, definitions.AuthResultFail)

		err := fmt.Errorf("authentication failed due to brute force protection")
		sp.RecordError(err)

		return nil, err
	}

	if res := auth.HandleFeatures(ctx); res != definitions.AuthResultOK && res != definitions.AuthResultUnset {
		auth.AuthFail(ctx)
		auth.FinishLogging(ctx, res)

		err := fmt.Errorf("authentication failed with feature result: %d", res)
		sp.RecordError(err)

		return nil, err
	}

	result := auth.HandlePassword(ctx)

	auth.FinishLogging(ctx, result)

	if result != definitions.AuthResultOK {
		err := fmt.Errorf("authentication failed with result: %d", result)
		sp.RecordError(err)

		return nil, err
	}

	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Set(definitions.SessionKeyUserBackend, uint8(auth.GetSourcePassDBBackend()))
		mgr.Set(definitions.SessionKeyUserBackendName, auth.GetUsedPassDBBackendName())
	}

	return n.userFromAuthState(auth)
}

// GetUserByUsername retrieves user details and attributes without performing password authentication.
func (n *NauthilusIdP) GetUserByUsername(ctx *gin.Context, username string, oidcCID string, samlEntityID string) (*backend.User, error) {
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

	auth.SetUsername(username)
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)

	if oidcCID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoOIDC))
	} else if samlEntityID != "" {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoSAML))
	} else {
		auth.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	}

	auth.FinishSetup(ctx)

	auth.SetNoAuth(true)

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
	}

	return n.userFromAuthState(auth)
}

func (n *NauthilusIdP) userFromAuthState(auth *core.AuthState) (*backend.User, error) {
	accountName, ok := auth.GetAccountOk()
	if !ok {
		return nil, fmt.Errorf("failed to get account name")
	}

	displayName := auth.GetDisplayName()
	uniqueID := auth.GetUniqueUserID()

	user := backend.NewUser(accountName, displayName, uniqueID)
	user.Attributes = auth.GetAttributes()
	user.TOTPSecretField = auth.GetTOTPSecretField()
	user.TOTPRecoveryField = auth.GetTOTPRecoveryField()

	return user, nil
}

// GetClaims retrieves user attributes and maps them to OIDC/SAML claims for a specific client.

func (n *NauthilusIdP) GetClaims(ctx *gin.Context, user *backend.User, client any, scopes []string) (map[string]any, map[string]any, error) {
	idTokenClaims := map[string]any{
		"sub":                user.Id,
		"name":               user.DisplayName,
		"preferred_username": user.Name,
	}
	accessTokenClaims := make(map[string]any)

	// Map attributes from backend using claim mappings when client is OIDCClient.
	if oidcClient, ok := client.(*config.OIDCClient); ok {
		// We need an AuthState to use FillIdTokenClaims
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

		auth.FillIdTokenClaims(&oidcClient.IdTokenClaims, idTokenClaims, scopes)
		auth.FillAccessTokenClaims(&oidcClient.AccessTokenClaims, accessTokenClaims, scopes)
	}

	return idTokenClaims, accessTokenClaims, nil
}
