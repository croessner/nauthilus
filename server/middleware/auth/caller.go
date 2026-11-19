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

package auth

import (
	"net/http"
	"slices"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
)

// CallerMethod names how a backchannel caller proved its identity.
type CallerMethod string

const (
	// CallerMethodBasic is an HTTP Basic credential of auth.backchannel.basic_auth.
	CallerMethodBasic CallerMethod = "basic_auth"

	// CallerMethodBearer is a backchannel OAuth service access token.
	CallerMethodBearer CallerMethod = "oidc_bearer"
)

// callerResponseKeyError is the JSON member of a refused caller's error message.
const callerResponseKeyError = "error"

// Caller is the authenticated principal of a backchannel request. Both credential kinds map to it, so a route
// authorizes Basic and Bearer callers through the same scopes.
//
// The unrestricted Basic credential holds no scope; it passes Grants for every scope instead. Code that must not
// honor it, such as the support routes, asks HasScope or HasAnyScope, which only know scopes the caller really holds.
type Caller struct {
	scopes       []string
	identity     string
	method       CallerMethod
	unrestricted bool
}

// NewScopedCaller returns a caller that holds exactly scopes.
func NewScopedCaller(method CallerMethod, identity string, scopes []string) *Caller {
	return &Caller{scopes: slices.Clone(scopes), identity: identity, method: method}
}

// NewUnrestrictedBasicCaller returns the caller of the unrestricted Basic credential. Only code that matched
// that credential itself may construct it, because it passes every management scope check.
func NewUnrestrictedBasicCaller(identity string) *Caller {
	return &Caller{identity: identity, method: CallerMethodBasic, unrestricted: true}
}

// Identity returns the Basic username or the client of the Bearer token; a nil caller has none.
func (c *Caller) Identity() string {
	if c == nil {
		return ""
	}

	return c.identity
}

// Method returns how the caller authenticated; a nil caller has no method.
func (c *Caller) Method() CallerMethod {
	if c == nil {
		return ""
	}

	return c.method
}

// Unrestricted reports whether the caller used the unrestricted Basic credential.
func (c *Caller) Unrestricted() bool {
	return c != nil && c.unrestricted
}

// HasScope reports whether the caller really holds scope.
func (c *Caller) HasScope(scope string) bool {
	return c != nil && scope != "" && slices.Contains(c.scopes, scope)
}

// HasAnyScope reports whether the caller really holds at least one of scopes.
func (c *Caller) HasAnyScope(scopes ...string) bool {
	return slices.ContainsFunc(scopes, c.HasScope)
}

// HasAllScopes reports whether the caller really holds every one of scopes.
func (c *Caller) HasAllScopes(scopes ...string) bool {
	return c != nil && !slices.ContainsFunc(scopes, func(scope string) bool { return !c.HasScope(scope) })
}

// Grants reports whether the caller may use a management route that requires one of scopes: the unrestricted
// Basic credential always may, every other caller needs one of them. A nil caller is granted nothing.
func (c *Caller) Grants(scopes ...string) bool {
	return c.Unrestricted() || c.HasAnyScope(scopes...)
}

// StoreCaller binds the authenticated caller to the request. Only the unrestricted Basic credential sets the
// Basic marker, which downstream code reads as full management access.
func StoreCaller(ctx *gin.Context, caller *Caller) {
	if ctx == nil || caller == nil {
		return
	}

	ctx.Set(definitions.CtxBackchannelCallerKey, caller)

	if caller.method == CallerMethodBasic {
		ctx.Set(definitions.CtxAuthMethodKey, string(CallerMethodBasic))
	}

	if caller.unrestricted {
		ctx.Set(definitions.CtxBasicAuthValidatedKey, true)
	}
}

// CallerFromContext returns the authenticated caller of the request, or nil when none authenticated.
func CallerFromContext(ctx *gin.Context) *Caller {
	if ctx == nil {
		return nil
	}

	value, exists := ctx.Get(definitions.CtxBackchannelCallerKey)
	if !exists {
		return nil
	}

	caller, _ := value.(*Caller)

	return caller
}

// AuthenticateBasicCaller resolves submitted Basic credentials to the configured backchannel caller, or nil when
// they match none. Every configured credential is compared, so the duration does not reveal which username exists.
func AuthenticateBasicCaller(cfg config.File, username, password string) *Caller {
	if cfg == nil || cfg.GetServer() == nil {
		return nil
	}

	basicAuth := cfg.GetServer().GetBasicAuth()
	if !basicAuth.IsEnabled() {
		return nil
	}

	var caller *Caller

	if ValidateBasicAuthCredentials(basicAuth.Unrestricted(), username, password) {
		caller = NewUnrestrictedBasicCaller(username)
	}

	users := basicAuth.GetUsers()
	for index := range users {
		if matchesBasicCredential(users[index].GetUsername(), users[index].GetPassword(), username, password) && caller == nil {
			caller = NewScopedCaller(CallerMethodBasic, username, users[index].GetScopes())
		}
	}

	return caller
}

// AuthorizeScopedBasicCaller authenticates presented Basic credentials for a route that requires scopes and is
// not behind the backchannel middleware, such as a custom hook. Only a credential that really holds one of
// requiredScopes is authorized, so the unrestricted credential is refused like a token without the scope.
//
// presented is false when the request carries no Basic credentials or Basic is disabled; nothing was written
// then and the route may fall back to Bearer. Otherwise the request is authorized or already aborted.
func AuthorizeScopedBasicCaller(
	ctx *gin.Context,
	cfg config.File,
	requiredScopes []string,
	missingScopeMessage string,
) (presented bool, authorized bool) {
	if ctx == nil || ctx.Request == nil || cfg == nil || !cfg.GetServer().GetBasicAuth().IsEnabled() {
		return false, false
	}

	username, password, ok := ctx.Request.BasicAuth()
	if !ok {
		return false, false
	}

	accounting := NewHTTPCallerAccounting(ctx, cfg, nil)

	caller := AuthenticateBasicCaller(cfg, username, password)
	if caller == nil {
		accounting.Reject("invalid basic credentials")
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return true, false
	}

	if !caller.HasAnyScope(requiredScopes...) {
		accounting.Deny()
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{callerResponseKeyError: missingScopeMessage})

		return true, false
	}

	StoreCaller(ctx, caller)
	accounting.Accept()

	return true, true
}
