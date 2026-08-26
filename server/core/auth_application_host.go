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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// authApplicationHost owns the private Gin context required by the admitted FSM execution.
type authApplicationHost struct {
	engine *gin.Engine
}

// newAuthApplicationHost constructs the private admitted-execution host.
func newAuthApplicationHost() *authApplicationHost {
	return &authApplicationHost{engine: gin.New()}
}

// newAuthState prepares the existing FSM host from transport-neutral application values.
func (s *authApplicationService) newAuthState(
	parent context.Context,
	input AuthInput,
) (*AuthState, *gin.Context, *CaptureResponseWriter, error) {
	deps, err := s.effectiveDeps(parent)
	if err != nil {
		return nil, nil, nil, err
	}

	capture := NewDefaultCaptureResponseWriter(ResponseDeps{
		Cfg:       deps.Cfg,
		Env:       deps.Env,
		Logger:    deps.Logger,
		WaitDelay: deps.HostServices.WaitDelay,
	})
	deps.Resp = capture

	ginCtx, err := s.host.newContext(parent, input)
	if err != nil {
		return nil, nil, nil, err
	}

	AttachPostActionExecutionGate(parent, ginCtx)
	auth := NewAuthStateFromContextWithDeps(ginCtx, deps).(*AuthState)

	tr := monittrace.New("nauthilus/auth")
	setupCtx, span := tr.Start(parent, "auth.setup",
		attribute.String("service", input.Service),
		attribute.String("mode", string(input.Mode)),
	)

	requestScope := auth.scopeRequestContext(setupCtx, ginCtx)

	defer requestScope.Restore()
	defer span.End()

	auth.SetProtocol(&config.Protocol{})
	auth.ApplyCredentials(input.Credentials)
	auth.ApplyContextData(input.Context)
	applyAuthIDPContext(auth, input.IDP)

	if input.AuthLoginAttempt > 0 {
		auth.Request.AuthLoginAttempt = input.AuthLoginAttempt
		auth.SyncLoginAttemptsFromAttemptOrdinal(input.AuthLoginAttempt)
	}

	auth.postResolvDNS(ginCtx.Request.Context())
	auth.InitMethodAndUserAgent()
	auth.WithDefaults(ginCtx)
	auth.SetStatusCodes(input.Service)
	auth.SetOperationMode(ginCtx)
	auth.traceSetupDetails(span)
	logProcessingRequest(ginCtx, auth)

	return auth, ginCtx, capture, nil
}

// applyAuthIDPContext installs detached protocol, attribute-release, and affinity values on the compatibility host.
func applyAuthIDPContext(auth *AuthState, idpContext AuthIDPContext) {
	if auth == nil {
		return
	}

	if !idpRequestContextIsZero(idpContext.Request) {
		auth.Runtime.IDPContext = idpContext.Request.toIDPRequestContext()
	}

	auth.Runtime.IdentityAttributeRequest = idpContext.IdentityAttributeRequest.Clone()
	auth.Runtime.RemoteBackendRef = idpContext.ExistingBackendRef
}

// idpRequestContextIsZero reports whether no bounded protocol request value was supplied.
func idpRequestContextIsZero(request AuthIDPRequestContext) bool {
	return request.GrantType == "" && request.RedirectURI == "" && len(request.RequestedScopes) == 0
}

// newContext builds the private Gin context used only inside an admitted Decision Session.
func (h *authApplicationHost) newContext(parent context.Context, input AuthInput) (*gin.Context, error) {
	path := authApplicationPath(input)
	recorder := httptest.NewRecorder()
	ginCtx := gin.CreateTestContextOnly(recorder, h.engine)

	request, err := http.NewRequestWithContext(parent, authApplicationHTTPMethod(input), path, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build application request: %w", err)
	}

	ginCtx.Request = request

	for name, values := range input.Context.RequestMetadata {
		for _, value := range values {
			ginCtx.Request.Header.Add(name, value)
		}
	}

	if input.Service == definitions.ServBasic {
		input.Credentials.Password.WithString(func(password string) {
			ginCtx.Request.SetBasicAuth(input.Credentials.Username, password)
		})
	}

	ginCtx.Set(definitions.CtxCategoryKey, definitions.CatAuth)
	ginCtx.Set(definitions.CtxServiceKey, input.Service)
	ginCtx.Set(definitions.CtxGUIDKey, authApplicationCorrelationID(input.CorrelationID))
	ginCtx.Set(definitions.CtxLocalCacheAuthKey, false)
	ginCtx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	if claims := parent.Value(authApplicationOIDCClaimsKey); claims != nil {
		ginCtx.Set(definitions.CtxOIDCClaimsKey, claims)
	}

	return ginCtx, nil
}

// authApplicationHTTPMethod preserves real HTTP GET/POST semantics and defaults internal requests to POST.
func authApplicationHTTPMethod(input AuthInput) string {
	transport := input.Context.Transport
	if transport.Kind != requestPolicyTransportHTTP {
		return http.MethodPost
	}

	switch transport.HTTPMethod {
	case http.MethodGet:
		return http.MethodGet
	case http.MethodPost:
		return http.MethodPost
	default:
		return http.MethodPost
	}
}

// authApplicationPath maps neutral operation controls into the private FSM request.
func authApplicationPath(input AuthInput) string {
	path := "/grpc/auth/v1/Authenticate"

	switch input.Mode {
	case AuthModeLookupIdentity:
		path = "/grpc/auth/v1/LookupIdentity"
	case AuthModeListAccounts:
		path = "/grpc/auth/v1/ListAccounts"
	}

	if route := input.Context.Transport.HTTPRoute; route != "" {
		path = route
	}

	query := make(url.Values)

	switch input.Mode {
	case AuthModeLookupIdentity:
		query.Set(authInputFieldMode, authModeNoAuth)
	case AuthModeListAccounts:
		query.Set(authInputFieldMode, string(AuthModeListAccounts))
	}

	if input.DisableMemoryCache {
		query.Set("in-memory", "0")
	}

	if input.DisableCache {
		query.Set("cache", "0")
	}

	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}

	return path
}

// authApplicationCorrelationID preserves a transport correlation ID or creates a request-local fallback.
func authApplicationCorrelationID(input string) string {
	if input != "" {
		return input
	}

	return ksuid.New().String()
}
