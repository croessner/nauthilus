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

package router_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	handlerapiv1 "github.com/croessner/nauthilus/v3/server/handler/api/v1"
	handlerbackchannel "github.com/croessner/nauthilus/v3/server/handler/backchannel"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	handleridp "github.com/croessner/nauthilus/v3/server/handler/frontend/idp"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/openapi"
	approuter "github.com/croessner/nauthilus/v3/server/router"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	textlanguage "golang.org/x/text/language"
)

const (
	contractMethodDelete   = "delete"
	contractMethodGet      = "get"
	contractMethodPost     = "post"
	contractMethodPut      = "put"
	contractRouteAPIPrefix = "/api/v1/"

	contractGateSyntheticName               = "synthetic"
	contractPathAuthJSON                    = "/api/v1/auth/json"
	contractPathConfigLoad                  = "/api/v1/config/load"
	contractPathMFABackchannelTOTP          = "/api/v1/mfa-backchannel/totp"
	contractPathMFABackchannelRecoveryCodes = "/api/v1/mfa-backchannel/totp/recovery-codes"
	contractPathMFABackchannelWebAuthn      = "/api/v1/mfa-backchannel/webauthn/credential"
	contractPathBrowserMFARecoveryRegister  = "/mfa/recovery/register"
	contractPathBrowserMFATOTPRegister      = "/mfa/totp/register"
	contractPathManagementOpenAPIJSON       = "/api/v1/openapi.json"
	contractPathManagementOpenAPIYAML       = "/api/v1/openapi.yaml"
)

type routeOperation struct {
	method string
	path   string
}

type routeExceptionList struct {
	exactRoutes  map[routeOperation]string
	exactPaths   map[string]string
	pathPrefixes map[string]string
	name         string
}

type routeDriftGate struct {
	routes     map[routeOperation]struct{}
	documented map[routeOperation]struct{}
	exceptions []routeExceptionList
	name       string
}

type routeContractDocument struct {
	operations map[routeOperation]*openapi3.Operation
}

type routeContractLangManager struct{}

func TestManagementRoutesMatchOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	document := loadRouteContractDocument(t, openapi.ManagementYAML())
	routes := routeSetFromGinRoutes(buildManagementContractRouter(t).Routes())
	gate := routeDriftGate{
		name:       "management",
		routes:     filterRouteSet(routes, hasAPIPrefix),
		documented: document.operationSet(),
		exceptions: managementRouteExceptions(),
	}

	if err := gate.validate(); err != nil {
		t.Fatal(err)
	}

	assertAPIV1OperationsDeclareProtectedSecurity(t, document.operations)
	assertManagementOpenAPIDocumentsUseBackchannelGuard(t, document.operations)
	assertManagementOIDCSessionsUseBackchannelGuard(t, buildManagementContractRouter(t))
}

func TestManagementRoutesDoNotExposeConfigLoad(t *testing.T) {
	gin.SetMode(gin.TestMode)

	document := loadRouteContractDocument(t, openapi.ManagementYAML())
	routes := routeSetFromGinRoutes(buildManagementContractRouter(t).Routes())
	operation := routeOperation{method: contractMethodGet, path: contractPathConfigLoad}

	if _, ok := routes[operation]; ok {
		t.Fatalf("%s is still registered", operation.label())
	}

	if _, ok := document.operationSet()[operation]; ok {
		t.Fatalf("%s is still documented", operation.label())
	}
}

func TestIDPRoutesMatchOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)

	document := loadRouteContractDocument(t, openapi.IDPYAML())
	routes := routeSetFromGinRoutes(buildIDPContractRouter(t).Routes())
	gate := routeDriftGate{
		name:       "idp",
		routes:     filterRouteSet(routes, withoutAPIPrefix),
		documented: document.operationSet(),
		exceptions: idpRouteExceptions(),
	}

	if err := gate.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRouteDriftGateRejectsMissingCoverage(t *testing.T) {
	documented := routeOperationSet(routeOperation{method: contractMethodGet, path: contractPathAuthJSON})
	routes := routeOperationSet(
		routeOperation{method: contractMethodGet, path: contractPathAuthJSON},
		routeOperation{method: contractMethodPost, path: "/api/v1/new-stable-route"},
	)

	gate := routeDriftGate{name: contractGateSyntheticName, routes: routes, documented: documented}

	err := gate.validate()
	if err == nil {
		t.Fatal("route drift gate accepted an undocumented stable route")
	}

	if !strings.Contains(err.Error(), "POST /api/v1/new-stable-route") {
		t.Fatalf("error = %q, want missing route label", err)
	}
}

func TestRouteDriftGateRejectsStaleOperations(t *testing.T) {
	documented := routeOperationSet(
		routeOperation{method: contractMethodGet, path: contractPathAuthJSON},
		routeOperation{method: contractMethodDelete, path: "/api/v1/deleted-route"},
	)
	routes := routeOperationSet(routeOperation{method: contractMethodGet, path: contractPathAuthJSON})

	gate := routeDriftGate{name: contractGateSyntheticName, routes: routes, documented: documented}

	err := gate.validate()
	if err == nil {
		t.Fatal("route drift gate accepted a stale OpenAPI operation")
	}

	if !strings.Contains(err.Error(), "DELETE /api/v1/deleted-route") {
		t.Fatalf("error = %q, want stale operation label", err)
	}
}

func buildManagementContractRouter(t *testing.T) *gin.Engine {
	t.Helper()

	cfg := routeContractConfig()
	deps := routeContractDeps(cfg)

	engine := gin.New()
	engine.Use(gin.Recovery())

	if err := handlerbackchannel.Setup(engine, deps); err != nil {
		t.Fatalf("register backchannel routes: %v", err)
	}

	handlerapiv1.NewMFAAPI(deps).Register(engine)

	return engine
}

// assertManagementOIDCSessionsUseBackchannelGuard verifies session management is not mounted raw.
func assertManagementOIDCSessionsUseBackchannelGuard(t *testing.T, router http.Handler) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/sessions/user1", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/oidc/sessions/user1 status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func buildIDPContractRouter(t *testing.T) *gin.Engine {
	t.Helper()

	cfg := routeContractConfig()
	deps := routeContractDeps(cfg)

	engine := approuter.NewRouter(cfg).WithIDPOpenAPI().Build()

	frontend := handleridp.NewFrontendHandler(deps)
	frontend.Register(engine)

	nauthilusIDP := idp.NewNauthilusIDP(deps)
	handleridp.NewOIDCHandler(deps, nauthilusIDP, frontend).Register(engine)
	handleridp.NewSAMLHandler(deps, nauthilusIDP).Register(engine)

	return engine
}

func routeContractConfig() *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			BasicAuth: config.BasicAuth{
				Enabled:  true,
				Username: "api-client",
				Password: secret.New("api-secret-1234"),
			},
			Frontend: config.Frontend{
				Enabled:               true,
				EncryptionSecret:      secret.New("0123456789abcdef"),
				HTMLStaticContentPath: "static/templates",
				DefaultLanguage:       "en",
			},
		},
		IDP: &config.IDPSection{
			OIDC: config.OIDCConfig{
				Enabled: true,
				Issuer:  "https://nauthilus.example.com",
			},
			SAML2: config.SAML2Config{
				Enabled:  true,
				EntityID: "https://nauthilus.example.com/saml/metadata",
			},
		},
	}
}

func routeContractDeps(cfg config.File) *handlerdeps.Deps {
	env := config.NewTestEnvironmentConfig()
	config.SetTestEnvironmentConfig(env)
	util.SetDefaultEnvironment(env)

	return &handlerdeps.Deps{
		Cfg:          cfg,
		Env:          env,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		LangManager:  routeContractLangManager{},
		TokenFlusher: idp.NewRedisTokenStorage(nil, "test:"),
	}
}

func managementRouteExceptions() []routeExceptionList {
	return []routeExceptionList{
		{
			name: "Lua custom hook endpoints",
			pathPrefixes: map[string]string{
				"/api/v1/custom/": "runtime-configured Lua hook endpoints have per-hook scope checks and are not stable OpenAPI operations",
			},
		},
		{
			name: "MFA proxy backchannel endpoints",
			exactRoutes: routeOperationReasons(
				"MFA proxy backchannel endpoints are internal authority-to-edge plumbing for Lua proxy backends",
				routeOperation{method: contractMethodPost, path: contractPathMFABackchannelTOTP},
				routeOperation{method: contractMethodDelete, path: contractPathMFABackchannelTOTP},
				routeOperation{method: contractMethodPost, path: contractPathMFABackchannelRecoveryCodes},
				routeOperation{method: contractMethodDelete, path: contractPathMFABackchannelRecoveryCodes},
				routeOperation{method: contractMethodGet, path: contractPathMFABackchannelWebAuthn},
				routeOperation{method: contractMethodPost, path: contractPathMFABackchannelWebAuthn},
				routeOperation{method: contractMethodPut, path: contractPathMFABackchannelWebAuthn},
				routeOperation{method: contractMethodDelete, path: contractPathMFABackchannelWebAuthn},
			),
		},
	}
}

func idpRouteExceptions() []routeExceptionList {
	return []routeExceptionList{
		{
			name: "Generated static asset routes",
			exactPaths: map[string]string{
				"/favicon.ico": "generated static asset route served by the browser frontend",
			},
			pathPrefixes: map[string]string{
				"/static/": "generated static asset routes served by the browser frontend",
			},
		},
		{
			name:        "Browser-only MFA self-service routes",
			exactRoutes: browserOnlyMFARouteReasons(),
		},
		{
			name: "Browser-only device error routes",
			exactRoutes: routeOperationReasons(
				"device verification error pages are browser-only flow pages, not stable protocol operations",
				routeOperation{method: contractMethodGet, path: "/oidc/device/verify/failed"},
			),
		},
	}
}

func browserOnlyMFARouteReasons() map[routeOperation]string {
	return routeOperationReasons(
		"browser MFA self-service pages are session HTML flows, not stable API operations",
		routeOperation{method: contractMethodGet, path: "/mfa/register/home"},
		routeOperation{method: contractMethodGet, path: contractPathBrowserMFATOTPRegister},
		routeOperation{method: contractMethodPost, path: contractPathBrowserMFATOTPRegister},
		routeOperation{method: contractMethodDelete, path: "/mfa/totp"},
		routeOperation{method: contractMethodGet, path: "/mfa/webauthn/register"},
		routeOperation{method: contractMethodGet, path: "/mfa/webauthn/register/begin"},
		routeOperation{method: contractMethodPost, path: "/mfa/webauthn/register/finish"},
		routeOperation{method: contractMethodDelete, path: "/mfa/webauthn"},
		routeOperation{method: contractMethodGet, path: "/mfa/webauthn/devices"},
		routeOperation{method: contractMethodDelete, path: "/mfa/webauthn/device/{id}"},
		routeOperation{method: contractMethodPost, path: "/mfa/webauthn/device/{id}/name"},
		routeOperation{method: contractMethodGet, path: contractPathBrowserMFARecoveryRegister},
		routeOperation{method: contractMethodPost, path: contractPathBrowserMFARecoveryRegister},
		routeOperation{method: contractMethodPost, path: "/mfa/recovery/register/save"},
		routeOperation{method: contractMethodPost, path: "/mfa/recovery/generate"},
		routeOperation{method: contractMethodGet, path: "/mfa/register/continue"},
		routeOperation{method: contractMethodGet, path: "/mfa/register/cancel"},
	)
}

func (gate routeDriftGate) validate() error {
	missingCoverage := gate.routesMissingCoverage()
	staleOperations := gate.documentedOperationsMissingRoutes()

	if len(missingCoverage) == 0 && len(staleOperations) == 0 {
		return nil
	}

	return fmt.Errorf(
		"%s route contract drift detected%s%s",
		gate.name,
		formatRouteOperationList("\nundocumented Gin routes", missingCoverage),
		formatRouteOperationList("\nstale OpenAPI operations", staleOperations),
	)
}

func (gate routeDriftGate) routesMissingCoverage() []routeOperation {
	missing := make([]routeOperation, 0)

	for route := range gate.routes {
		if _, ok := gate.documented[route]; ok {
			continue
		}

		if gate.isRouteException(route) {
			continue
		}

		missing = append(missing, route)
	}

	sortRouteOperations(missing)

	return missing
}

func (gate routeDriftGate) documentedOperationsMissingRoutes() []routeOperation {
	missing := make([]routeOperation, 0)

	for operation := range gate.documented {
		if _, ok := gate.routes[operation]; ok {
			continue
		}

		missing = append(missing, operation)
	}

	sortRouteOperations(missing)

	return missing
}

func (gate routeDriftGate) isRouteException(route routeOperation) bool {
	for _, exceptions := range gate.exceptions {
		if exceptions.allows(route) {
			return true
		}
	}

	return gate.isLocalizedAlias(route)
}

func (gate routeDriftGate) isLocalizedAlias(route routeOperation) bool {
	baseRoute, ok := route.withoutLanguageAlias()
	if !ok {
		return false
	}

	if _, documented := gate.documented[baseRoute]; documented {
		return true
	}

	for _, exceptions := range gate.exceptions {
		if exceptions.allows(baseRoute) {
			return true
		}
	}

	return false
}

func (exceptions routeExceptionList) allows(route routeOperation) bool {
	if _, ok := exceptions.exactRoutes[route]; ok {
		return true
	}

	if _, ok := exceptions.exactPaths[route.path]; ok {
		return true
	}

	for prefix := range exceptions.pathPrefixes {
		if strings.HasPrefix(route.path, prefix) {
			return true
		}
	}

	return false
}

func loadRouteContractDocument(t *testing.T, content []byte) routeContractDocument {
	t.Helper()

	ctx := context.Background()
	loader := openapi3.NewLoader()
	loader.Context = ctx
	loader.IsExternalRefsAllowed = false

	doc, err := loader.LoadFromData(content)
	if err != nil {
		t.Fatalf("parse OpenAPI document: %v", err)
	}

	if err := doc.Validate(ctx); err != nil {
		t.Fatalf("validate OpenAPI document: %v", err)
	}

	return routeContractDocument{operations: routeOperationsFromOpenAPI(doc)}
}

func routeOperationsFromOpenAPI(doc *openapi3.T) map[routeOperation]*openapi3.Operation {
	operations := make(map[routeOperation]*openapi3.Operation)

	for _, path := range doc.Paths.Keys() {
		pathItem := doc.Paths.Value(path)
		if pathItem == nil {
			continue
		}

		for method, operation := range pathItem.Operations() {
			key := routeOperation{method: strings.ToLower(method), path: path}
			operations[key] = operation
		}
	}

	return operations
}

func routeSetFromGinRoutes(routes gin.RoutesInfo) map[routeOperation]struct{} {
	operations := make(map[routeOperation]struct{}, len(routes))
	for _, route := range routes {
		operations[routeOperation{
			method: strings.ToLower(route.Method),
			path:   normalizeGinRoutePath(route.Path),
		}] = struct{}{}
	}

	return operations
}

func normalizeGinRoutePath(path string) string {
	segments := strings.Split(path, "/")
	for idx, segment := range segments {
		if !strings.HasPrefix(segment, ":") {
			continue
		}

		segments[idx] = "{" + strings.TrimPrefix(segment, ":") + "}"
	}

	return strings.Join(segments, "/")
}

func filterRouteSet(
	routes map[routeOperation]struct{},
	keep func(routeOperation) bool,
) map[routeOperation]struct{} {
	filtered := make(map[routeOperation]struct{})

	for route := range routes {
		if keep(route) {
			filtered[route] = struct{}{}
		}
	}

	return filtered
}

func hasAPIPrefix(route routeOperation) bool {
	return strings.HasPrefix(route.path, contractRouteAPIPrefix)
}

func withoutAPIPrefix(route routeOperation) bool {
	return !hasAPIPrefix(route)
}

func routeOperationSet(operations ...routeOperation) map[routeOperation]struct{} {
	set := make(map[routeOperation]struct{}, len(operations))
	for _, operation := range operations {
		set[operation] = struct{}{}
	}

	return set
}

func routeOperationReasons(reason string, operations ...routeOperation) map[routeOperation]string {
	reasons := make(map[routeOperation]string, len(operations))
	for _, operation := range operations {
		reasons[operation] = reason
	}

	return reasons
}

func (document routeContractDocument) operationSet() map[routeOperation]struct{} {
	set := make(map[routeOperation]struct{}, len(document.operations))
	for operation := range document.operations {
		set[operation] = struct{}{}
	}

	return set
}

func assertAPIV1OperationsDeclareProtectedSecurity(
	t *testing.T,
	operations map[routeOperation]*openapi3.Operation,
) {
	t.Helper()

	for key, operation := range operations {
		if !strings.HasPrefix(key.path, contractRouteAPIPrefix) {
			continue
		}

		if !hasProtectedSecurityScheme(operation) {
			t.Fatalf("%s must declare a protected /api/v1 security scheme", key.label())
		}
	}
}

func assertManagementOpenAPIDocumentsUseBackchannelGuard(
	t *testing.T,
	operations map[routeOperation]*openapi3.Operation,
) {
	t.Helper()

	for _, key := range managementOpenAPIDocumentOperations() {
		operation, ok := operations[key]
		if !ok {
			t.Fatalf("%s missing from management OpenAPI document", key.label())
		}

		if !hasExactSecurityAlternatives(operation, "backchannelBasic", "backchannelBearer") {
			t.Fatalf("%s must stay protected by the backchannel Basic/Bearer guard", key.label())
		}
	}
}

func managementOpenAPIDocumentOperations() []routeOperation {
	return []routeOperation{
		{method: contractMethodGet, path: contractPathManagementOpenAPIYAML},
		{method: contractMethodGet, path: contractPathManagementOpenAPIJSON},
	}
}

func hasProtectedSecurityScheme(operation *openapi3.Operation) bool {
	for _, scheme := range operationSecuritySchemes(operation) {
		switch scheme {
		case "backchannelBasic", "backchannelBearer", "sessionCookie", "userBasic":
			return true
		}
	}

	return false
}

func hasExactSecurityAlternatives(operation *openapi3.Operation, expected ...string) bool {
	if operation == nil || operation.Security == nil {
		return false
	}

	requirements := *operation.Security
	if len(requirements) != len(expected) {
		return false
	}

	actual := operationSecuritySchemes(operation)
	sort.Strings(actual)
	sort.Strings(expected)

	return strings.Join(actual, "\x00") == strings.Join(expected, "\x00")
}

func operationSecuritySchemes(operation *openapi3.Operation) []string {
	if operation == nil || operation.Security == nil {
		return nil
	}

	schemes := make([]string, 0, len(*operation.Security))
	for _, requirement := range *operation.Security {
		if len(requirement) != 1 {
			continue
		}

		for scheme := range requirement {
			schemes = append(schemes, scheme)
		}
	}

	return schemes
}

func formatRouteOperationList(title string, operations []routeOperation) string {
	if len(operations) == 0 {
		return ""
	}

	labels := make([]string, 0, len(operations))
	for _, operation := range operations {
		labels = append(labels, operation.label())
	}

	return title + ":\n  - " + strings.Join(labels, "\n  - ")
}

func sortRouteOperations(operations []routeOperation) {
	sort.Slice(operations, func(i, j int) bool {
		if operations[i].path == operations[j].path {
			return operations[i].method < operations[j].method
		}

		return operations[i].path < operations[j].path
	})
}

func (operation routeOperation) withoutLanguageAlias() (routeOperation, bool) {
	const languageAliasSuffix = "/{languageTag}"

	if !strings.HasSuffix(operation.path, languageAliasSuffix) {
		return routeOperation{}, false
	}

	return routeOperation{
		method: operation.method,
		path:   strings.TrimSuffix(operation.path, languageAliasSuffix),
	}, true
}

func (operation routeOperation) label() string {
	return strings.ToUpper(operation.method) + " " + operation.path
}

func (routeContractLangManager) GetBundle() *i18n.Bundle {
	return i18n.NewBundle(textlanguage.English)
}

func (routeContractLangManager) GetMatcher() textlanguage.Matcher {
	return textlanguage.NewMatcher([]textlanguage.Tag{textlanguage.English})
}

func (routeContractLangManager) GetTags() []textlanguage.Tag {
	return []textlanguage.Tag{textlanguage.English}
}
