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
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// NauthilusIdP implements the IdentityProvider interface using Nauthilus core.
type NauthilusIdP struct {
	deps   *deps.Deps
	tracer monittrace.Tracer
}

// NewNauthilusIdP creates a new instance of NauthilusIdP.
func NewNauthilusIdP(d *deps.Deps) *NauthilusIdP {
	return &NauthilusIdP{
		deps:   d,
		tracer: monittrace.New("nauthilus/idp"),
	}
}

// FindClient returns an OIDC client by its ID.
func (n *NauthilusIdP) FindClient(clientID string) (*config.OIDCClient, bool) {
	for _, client := range n.deps.Cfg.GetIdP().OIDC.Clients {
		if client.ClientID == clientID {
			return &client, true
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

// IssueTokens generates an ID token and an access token for the given OIDC session.
func (n *NauthilusIdP) IssueTokens(ctx context.Context, session *OIDCSession) (string, string, error) {
	_, sp := n.tracer.Start(ctx, "idp.issue_tokens",
		attribute.String("client_id", session.ClientID),
		attribute.String("user_id", session.UserID),
	)
	defer sp.End()

	issuer := n.deps.Cfg.GetIdP().OIDC.Issuer
	signingKey, err := n.deps.Cfg.GetIdP().OIDC.GetSigningKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// Load private key
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(signingKey))
	if err != nil {
		sp.RecordError(err)

		return "", "", fmt.Errorf("failed to parse signing key: %w", err)
	}

	now := time.Now()

	// ID Token Claims
	idClaims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       session.UserID,
		"aud":       session.ClientID,
		"exp":       now.Add(1 * time.Hour).Unix(),
		"iat":       now.Unix(),
		"auth_time": session.AuthTime.Unix(),
	}

	// Add mapped claims from session
	for k, v := range session.Claims {
		idClaims[k] = v
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)

	idTokenString, err := idToken.SignedString(key)
	if err != nil {
		sp.RecordError(err)

		return "", "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	// Access Token Claims (simplified)
	accessClaims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   session.UserID,
		"aud":   session.ClientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": strings.Join(session.Scopes, " "),
	}

	// Add basic info to access token as well
	if v, ok := session.Claims["name"]; ok {
		accessClaims["name"] = v
	}
	if v, ok := session.Claims["preferred_username"]; ok {
		accessClaims["preferred_username"] = v
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)

	accessTokenString, err := accessToken.SignedString(key)
	if err != nil {
		sp.RecordError(err)

		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return idTokenString, accessTokenString, nil
}

// IssueLogoutToken generates a logout token for the given client and user.
func (n *NauthilusIdP) IssueLogoutToken(ctx context.Context, clientID string, userID string) (string, error) {
	_, sp := n.tracer.Start(ctx, "idp.issue_logout_token",
		attribute.String("client_id", clientID),
		attribute.String("user_id", userID),
	)
	defer sp.End()

	signingKey, err := n.deps.Cfg.GetIdP().OIDC.GetSigningKey()
	if err != nil {
		return "", err
	}

	issuer := n.deps.Cfg.GetIdP().OIDC.Issuer

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(signingKey))
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": userID,
		"aud": clientID,
		"iat": time.Now().Unix(),
		"jti": ksuid.New().String(),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = "default"

	return token.SignedString(key)
}

// ValidateToken parses and validates a signed JWT token.
func (n *NauthilusIdP) ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	_, sp := n.tracer.Start(ctx, "idp.validate_token")
	defer sp.End()

	signingKey, err := n.deps.Cfg.GetIdP().OIDC.GetSigningKey()
	if err != nil {
		sp.RecordError(err)

		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(signingKey))
	if err != nil {
		sp.RecordError(err)

		return nil, fmt.Errorf("failed to parse signing key: %w", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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

	auth := core.NewAuthStateWithSetupWithDeps(ctx, n.deps.Auth()).(*core.AuthState)
	auth.SetUsername(username)
	auth.SetPassword(password)
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)

	result := auth.HandlePassword(ctx)
	if result != definitions.AuthResultOK {
		err := fmt.Errorf("authentication failed with result: %d", result)
		sp.RecordError(err)

		return nil, err
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

	auth := core.NewAuthStateWithSetupWithDeps(ctx, n.deps.Auth()).(*core.AuthState)
	auth.SetUsername(username)
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)
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

	return user, nil
}

// GetClaims retrieves user attributes and maps them to OIDC/SAML claims for a specific client.
func (n *NauthilusIdP) GetClaims(user *backend.User, client any) (map[string]any, error) {
	claims := make(map[string]any)

	// Standard fixed claims
	claims["sub"] = user.Id
	claims["name"] = user.DisplayName
	claims["preferred_username"] = user.Name

	// Map attributes from backend using FillIdTokenClaims if client is OIDCClient
	if oidcClient, ok := client.(*config.OIDCClient); ok {
		// We need an AuthState to use FillIdTokenClaims
		// We can create a lightweight AuthState just for mapping
		auth := &core.AuthState{}
		auth.ReplaceAllAttributes(user.Attributes)

		auth.FillIdTokenClaims(&oidcClient.Claims, claims)
	}

	return claims, nil
}
