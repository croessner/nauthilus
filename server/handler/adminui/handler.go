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

// Package adminui provides internal admin UI routes and supporting services.
package adminui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/custom"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	mdi18n "github.com/croessner/nauthilus/server/middleware/i18n"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/server/middleware/securityheaders"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// AuthMode selects the UI authentication mode for admin pages.
type AuthMode string

const (
	// AuthModeIDPSession reuses the authenticated IdP browser session.
	AuthModeIDPSession AuthMode = "idp_session"
	// AuthModeLocalAdmin uses dedicated local administrator credentials.
	AuthModeLocalAdmin AuthMode = "local_admin"
)

const (
	hookTesterMaxEnvelopeBytes        = 1 << 20   // 1 MiB
	hookTesterMaxRequestBodyBytes     = 256 << 10 // 256 KiB
	hookTesterMaxResponsePreviewBytes = 256 << 10 // 256 KiB
	adminLocalAuthSessionKey          = "admin_local_authenticated"
	adminLocalUserSessionKey          = "admin_local_username"
	adminUIDefaultBasePath            = "/admin"
)

// ModuleDescriptor stores navigation and render metadata for one admin module.
type ModuleDescriptor struct {
	ID           string
	Title        string
	Route        string
	Partial      string
	FeatureGuard func(cfg config.File) bool
}

type localizedModule struct {
	ID    string
	Title string
	Route string
}

// BruteForceService abstracts brute-force operations for handler and test reuse.
type BruteForceService interface {
	List(ctx *gin.Context)
	FreeIP(ctx *gin.Context)
	FreeUser(ctx *gin.Context)
}

// ClickhouseService abstracts ClickHouse runtime querying and aggregations.
type ClickhouseService interface {
	Query(ctx *gin.Context) (any, error)
}

// HookTesterService abstracts internal custom-hook execution.
type HookTesterService interface {
	Send(ctx *gin.Context) (any, error)
}

// Handler assembles admin UI routes and delegates feature logic to services.
type Handler struct {
	deps           *handlerdeps.Deps
	authMode       AuthMode
	apiOIDCEnabled bool
	validator      oidcbearer.TokenValidator
	modules        []ModuleDescriptor
	bruteforce     BruteForceService
	clickhouse     ClickhouseService
	hooks          HookTesterService
}

// New creates a new admin UI handler.
func New(
	deps *handlerdeps.Deps,
	authMode AuthMode,
	apiOIDCEnabled bool,
	validator oidcbearer.TokenValidator,
	bruteforce BruteForceService,
	clickhouse ClickhouseService,
	hooks HookTesterService,
) *Handler {
	basePath := adminUIDefaultBasePath
	if deps != nil && deps.Cfg != nil {
		basePath = deps.Cfg.GetServer().GetAdminUI().GetBasePath()
	}

	return &Handler{
		deps:           deps,
		authMode:       authMode,
		apiOIDCEnabled: apiOIDCEnabled,
		validator:      validator,
		modules:        buildModuleRegistry(basePath),
		bruteforce:     withBruteForceFallback(deps, bruteforce),
		clickhouse:     withClickhouseFallback(deps, validator, clickhouse),
		hooks:          withHookFallback(deps, validator, hooks),
	}
}

func buildModuleRegistry(basePath string) []ModuleDescriptor {
	allow := func(_ config.File) bool { return true }

	return []ModuleDescriptor{
		{ID: "bruteforce", Title: "Brute Force", Route: basePath + "/partial/bruteforce", Partial: "partials_bruteforce.html", FeatureGuard: allow},
		{ID: "clickhouse", Title: "ClickHouse Runtime", Route: basePath + "/partial/clickhouse", Partial: "partials_clickhouse.html", FeatureGuard: allow},
		{ID: "hooktester", Title: "Hook Tester", Route: basePath + "/partial/hooktester", Partial: "partials_hooktester.html", FeatureGuard: allow},
	}
}

// Register wires routes under /admin and /admin/api.
// /admin and /admin/partial/* always use authMode.
// /admin/api/* may additionally accept OIDC bearer auth when apiOIDCEnabled is true.
func (h *Handler) Register(router gin.IRouter) {
	basePath := adminUIDefaultBasePath
	if h.deps != nil && h.deps.Cfg != nil {
		basePath = h.deps.Cfg.GetServer().GetAdminUI().GetBasePath()
	}

	base := router.Group(basePath, h.securityMiddleware(), h.sessionMiddleware(), h.languageMiddleware())
	login := base.Group("/login", h.csrfMiddleware())
	login.GET("", h.LocalAdminLoginPage)
	login.POST("", h.LocalAdminLoginSubmit)

	group := base.Group("", h.authMiddleware())
	ui := group.Group("", h.csrfMiddleware())
	ui.GET("", h.Index)
	ui.GET("/partial/dashboard", h.Dashboard)
	ui.GET("/partial/bruteforce", h.BruteForcePartial)
	ui.GET("/partial/clickhouse", h.ClickhousePartial)
	ui.GET("/partial/hooktester", h.HookTesterPartial)
	ui.POST("/logout", h.LocalAdminLogout)

	api := group.Group("/api", h.apiOIDCMiddleware(), h.csrfMiddleware())
	api.GET("/bruteforce/list", h.BruteForceList)
	api.POST("/bruteforce/free-ip", h.BruteForceFreeIP)
	api.POST("/bruteforce/free-user", h.BruteForceFreeUser)
	api.GET("/clickhouse/query", h.ClickhouseQuery)
	api.POST("/hooktester/send", h.HookTesterSend)
}

// LocalAdminLoginPage renders the dedicated local admin login page.
func (h *Handler) LocalAdminLoginPage(ctx *gin.Context) {
	if h.authMode != AuthModeLocalAdmin {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	if !h.isLocalAdminSourceIPAllowed(ctx) {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "source network is not permitted"})

		return
	}

	if h.isLocalAdminAuthenticatedSession(ctx) {
		ctx.Redirect(http.StatusFound, h.basePath())

		return
	}

	ctx.HTML(http.StatusOK, "admin_login.html", h.localAdminLoginData(ctx, ""))
}

// LocalAdminLoginSubmit validates credentials and creates a local admin session.
func (h *Handler) LocalAdminLoginSubmit(ctx *gin.Context) {
	if h.authMode != AuthModeLocalAdmin {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	if !h.isLocalAdminSourceIPAllowed(ctx) {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "source network is not permitted"})

		return
	}

	username := strings.TrimSpace(ctx.PostForm("username"))
	password := ctx.PostForm("password")

	if !h.validateLocalAdminCredentials(username, password) {
		ctx.HTML(http.StatusUnauthorized, "admin_login.html", h.localAdminLoginData(ctx, h.localize(ctx, "Invalid login or password")))

		return
	}

	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "missing session manager"})

		return
	}

	mgr.Set(adminLocalAuthSessionKey, true)
	mgr.Set(adminLocalUserSessionKey, username)

	ctx.Redirect(http.StatusFound, h.basePath())
}

// LocalAdminLogout clears the local admin session.
func (h *Handler) LocalAdminLogout(ctx *gin.Context) {
	if h.authMode != AuthModeLocalAdmin {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "missing session manager"})

		return
	}

	mgr.Delete(adminLocalAuthSessionKey)
	mgr.Delete(adminLocalUserSessionKey)

	ctx.Redirect(http.StatusFound, h.basePath()+"/login")
}

// Index renders the admin entry page.
func (h *Handler) Index(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "admin_layout.html", h.indexData(ctx))
}

// Dashboard renders the admin dashboard partial.
func (h *Handler) Dashboard(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "admin_dashboard.html", h.partialData(ctx))
}

// BruteForcePartial renders the brute-force module partial.
func (h *Handler) BruteForcePartial(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "partials_bruteforce.html", h.partialData(ctx))
}

// ClickhousePartial renders the ClickHouse module partial.
func (h *Handler) ClickhousePartial(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "partials_clickhouse.html", h.partialData(ctx))
}

// HookTesterPartial renders the hook tester module partial.
func (h *Handler) HookTesterPartial(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "partials_hooktester.html", h.partialData(ctx))
}

// BruteForceList returns current brute-force entries.
func (h *Handler) BruteForceList(ctx *gin.Context) {
	h.bruteforce.List(ctx)
}

// BruteForceFreeIP removes a blocked IP entry.
func (h *Handler) BruteForceFreeIP(ctx *gin.Context) {
	h.bruteforce.FreeIP(ctx)
}

// BruteForceFreeUser removes a blocked user entry.
func (h *Handler) BruteForceFreeUser(ctx *gin.Context) {
	h.bruteforce.FreeUser(ctx)
}

// ClickhouseQuery executes a ClickHouse runtime query.
func (h *Handler) ClickhouseQuery(ctx *gin.Context) {
	result, err := h.clickhouse.Query(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, result)
}

// HookTesterSend executes an internal custom-hook request.
func (h *Handler) HookTesterSend(ctx *gin.Context) {
	result, err := h.hooks.Send(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, result)
}

func (h *Handler) authMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if h == nil || h.deps == nil || h.deps.Cfg == nil {
			ctx.Next()

			return
		}

		switch h.authMode {
		case AuthModeLocalAdmin:
			h.handleLocalAdminAuth(ctx)
		case AuthModeIDPSession:
			fallthrough
		default:
			h.handleIDPSessionAuth(ctx)
		}
	}
}

func (h *Handler) handleIDPSessionAuth(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authenticated idp session"})

		return
	}

	account := strings.TrimSpace(mgr.GetString(definitions.SessionKeyAccount, ""))
	if account == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authenticated idp session"})

		return
	}

	username := strings.TrimSpace(mgr.GetString(definitions.SessionKeyUsername, account))
	result, ok := cookie.VerifyAuthResult(mgr, username)
	if !ok || result != definitions.AuthResultOK {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid idp session"})

		return
	}

	requiredRoleValues := h.deps.Cfg.GetServer().GetAdminUI().GetAuthorization().RequiredRoleValues
	if len(requiredRoleValues) > 0 && !h.hasAnyRequiredRoleValue(ctx, mgr, account, requiredRoleValues) {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required admin role"})

		return
	}

	ctx.Next()
}

func (h *Handler) handleLocalAdminAuth(ctx *gin.Context) {
	if !h.isLocalAdminSourceIPAllowed(ctx) {
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "source network is not permitted"})

		return
	}

	if h.isLocalAdminAuthenticatedSession(ctx) {
		ctx.Next()

		return
	}

	if strings.HasPrefix(ctx.Request.URL.Path, h.basePath()+"/api/") {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "local admin login required"})

		return
	}

	ctx.Redirect(http.StatusFound, h.basePath()+"/login")
	ctx.Abort()
}

func (h *Handler) isLocalAdminSourceIPAllowed(ctx *gin.Context) bool {
	cfg := h.getConfig()
	if cfg == nil {
		return false
	}

	network := cfg.GetServer().GetAdminUI().GetNetwork()
	if !network.EnforceForLocalAdmin {
		return false
	}

	address, err := netip.ParseAddr(strings.TrimSpace(ctx.ClientIP()))
	if err != nil {
		return false
	}

	for _, cidr := range network.SourceIPAllowlist {
		prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(cidr))
		if parseErr != nil {
			continue
		}

		if prefix.Contains(address) {
			return true
		}
	}

	return false
}

func (h *Handler) isLocalAdminAuthenticatedSession(ctx *gin.Context) bool {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return false
	}

	if !mgr.GetBool(adminLocalAuthSessionKey, false) {
		return false
	}

	return strings.TrimSpace(mgr.GetString(adminLocalUserSessionKey, "")) != ""
}

func (h *Handler) validateLocalAdminCredentials(username, password string) bool {
	cfg := h.getConfig()
	if cfg == nil {
		return false
	}

	localAdmin := cfg.GetServer().GetAdminUI().GetLocalAdmin()
	if !localAdmin.Enabled {
		return false
	}

	for _, user := range localAdmin.Users {
		if user.Username != username {
			continue
		}

		match, err := util.ComparePasswords(user.PasswordHash, password)
		if err != nil {
			return false
		}

		return match
	}

	return false
}

func (h *Handler) basePath() string {
	if h != nil && h.deps != nil && h.deps.Cfg != nil {
		return h.deps.Cfg.GetServer().GetAdminUI().GetBasePath()
	}

	return adminUIDefaultBasePath
}

func (h *Handler) localAdminLoginData(ctx *gin.Context, errorMessage string) gin.H {
	data := h.partialData(ctx)
	data["Title"] = h.localize(ctx, "Nauthilus Admin")
	data["AdminLoginTitle"] = h.localize(ctx, "Login")
	data["AdminLoginUsernameLabel"] = h.localize(ctx, "Username")
	data["AdminLoginPasswordLabel"] = h.localize(ctx, "Password")
	data["AdminLoginSubmit"] = h.localize(ctx, "Submit")
	data["AdminLoginError"] = strings.TrimSpace(errorMessage)
	data["AdminShowLogout"] = false

	return data
}

func (h *Handler) hasAnyRequiredRoleValue(
	ctx *gin.Context,
	mgr cookie.Manager,
	account string,
	requiredValues []string,
) bool {
	if len(requiredValues) == 0 {
		return true
	}

	roleValues := map[string]struct{}{}

	for _, value := range roleValuesFromClaims(oidcbearer.GetClaimsFromContext(ctx)) {
		roleValues[value] = struct{}{}
	}

	for _, value := range roleValuesFromSession(mgr) {
		roleValues[value] = struct{}{}
	}

	for _, value := range h.roleValuesFromBackendLookup(ctx, account) {
		roleValues[value] = struct{}{}
	}

	for _, required := range requiredValues {
		if _, ok := roleValues[strings.TrimSpace(required)]; ok {
			return true
		}
	}

	return false
}

func roleValuesFromClaims(claims map[string]any) []string {
	if len(claims) == 0 {
		return nil
	}

	keys := []string{"groups", "roles", "role", "memberOf", "member_of", "permissions", "entitlements"}

	return valuesByKeys(claims, keys)
}

func roleValuesFromSession(mgr cookie.Manager) []string {
	if mgr == nil {
		return nil
	}

	roles := make([]string, 0, 8)
	keys := []string{"groups", "roles", "role", "memberOf", "member_of", "permissions", "entitlements"}

	for _, key := range keys {
		value, ok := mgr.Get(key)
		if !ok {
			continue
		}

		roles = append(roles, flattenStringValues(value)...)
	}

	return roles
}

func (h *Handler) roleValuesFromBackendLookup(ctx *gin.Context, account string) []string {
	if h == nil || h.deps == nil || account == "" {
		return nil
	}

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	authState, ok := state.(*core.AuthState)
	if !ok || authState == nil {
		return nil
	}

	authState.SetUsername(account)
	authState.SetProtocol(config.NewProtocol(definitions.ProtoIDP))
	authState.SetNoAuth(true)

	if authState.HandlePassword(ctx) != definitions.AuthResultOK {
		return nil
	}

	attributes := authState.GetAttributesCopy()
	if len(attributes) == 0 {
		return nil
	}

	keys := map[string]struct{}{
		"groups":       {},
		"roles":        {},
		"role":         {},
		"memberof":     {},
		"member_of":    {},
		"permissions":  {},
		"entitlements": {},
	}

	roles := make([]string, 0, 8)

	for name, values := range attributes {
		if _, wanted := keys[strings.ToLower(strings.TrimSpace(name))]; !wanted {
			continue
		}

		roles = append(roles, flattenStringValues(values)...)
	}

	return roles
}

func valuesByKeys(data map[string]any, keys []string) []string {
	values := make([]string, 0, 8)
	for _, key := range keys {
		raw, ok := data[key]
		if !ok {
			continue
		}

		values = append(values, flattenStringValues(raw)...)
	}

	return values
}

func flattenStringValues(value any) []string {
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}

		return []string{trimmed}
	case []string:
		result := make([]string, 0, len(v))
		for _, item := range v {
			result = append(result, flattenStringValues(item)...)
		}

		return result
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			result = append(result, flattenStringValues(item)...)
		}

		return result
	default:
		return nil
	}
}

func (h *Handler) sessionMiddleware() gin.HandlerFunc {
	frontendSecret := []byte{}
	if h.deps != nil && h.deps.Cfg != nil {
		h.deps.Cfg.GetServer().GetFrontend().GetEncryptionSecret().WithBytes(func(value []byte) {
			if len(value) == 0 {
				return
			}

			frontendSecret = bytes.Clone(value)
		})
	}

	return cookie.Middleware(frontendSecret, h.getConfig(), h.getEnv())
}

func (h *Handler) securityMiddleware() gin.HandlerFunc {
	return securityheaders.New(securityheaders.MiddlewareConfig{Config: h.getConfig()}).Handler()
}

func (h *Handler) csrfMiddleware() gin.HandlerFunc {
	csrfMW := csrf.New()

	return func(ctx *gin.Context) {
		if ctx.GetBool("admin_api_oidc_authenticated") {
			ctx.Next()

			return
		}

		csrfMW(ctx)
	}
}

func (h *Handler) languageMiddleware() gin.HandlerFunc {
	if h.deps == nil || h.deps.Cfg == nil || h.deps.Logger == nil || h.deps.LangManager == nil {
		return func(ctx *gin.Context) {
			ctx.Next()
		}
	}

	return mdi18n.WithLanguage(h.deps.Cfg, h.deps.Logger, h.deps.LangManager)
}

func (h *Handler) apiOIDCMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !h.apiOIDCEnabled {
			ctx.Next()

			return
		}

		if !strings.HasPrefix(ctx.GetHeader("Authorization"), "Bearer ") {
			ctx.Next()

			return
		}

		if h.validator == nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "oidc validator is not configured"})

			return
		}

		requiredScopes := []string{}
		if h.deps != nil && h.deps.Cfg != nil {
			requiredScopes = h.deps.Cfg.GetServer().GetAdminUI().GetAuthorization().RequiredScopes
		}

		claims, ok := oidcbearer.EnforceBearerScopeAuth(ctx, h.validator, h.getConfig(), oidcbearer.EnforceBearerScopeAuthOptions{
			RequiredScopes:      requiredScopes,
			MissingScopeMessage: "missing required admin scope",
		})
		if !ok {
			return
		}

		requiredRoleValues := []string{}
		if h.deps != nil && h.deps.Cfg != nil {
			requiredRoleValues = h.deps.Cfg.GetServer().GetAdminUI().GetAuthorization().RequiredRoleValues
		}

		if len(requiredRoleValues) > 0 && !containsAnyRequiredRole(claims, requiredRoleValues) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required admin role"})

			return
		}

		ctx.Set("admin_api_oidc_authenticated", true)
		ctx.Next()
	}
}

func containsAnyRequiredRole(claims map[string]any, requiredValues []string) bool {
	if len(requiredValues) == 0 {
		return true
	}

	roleSet := map[string]struct{}{}
	for _, roleValue := range roleValuesFromClaims(claims) {
		roleSet[roleValue] = struct{}{}
	}

	for _, required := range requiredValues {
		if _, ok := roleSet[strings.TrimSpace(required)]; ok {
			return true
		}
	}

	return false
}

func (h *Handler) indexData(ctx *gin.Context) gin.H {
	data := h.partialData(ctx)
	data["Title"] = h.localize(ctx, "Nauthilus Admin")
	data["AdminDashboardTitle"] = h.localize(ctx, "Admin Dashboard")
	data["AdminDashboardHint"] = h.localize(ctx, "Operate local Nauthilus runtime features with HTMX.")

	return data
}

func (h *Handler) partialData(ctx *gin.Context) gin.H {
	return gin.H{
		"CSPNonce":                         securityheaders.NonceFromContext(ctx),
		"AdminBasePath":                    h.basePath(),
		"CSRFToken":                        csrf.Token(ctx),
		"Modules":                          h.localizedModules(ctx),
		"AdminShowLogout":                  h.authMode == AuthModeLocalAdmin,
		"AdminLogoutLabel":                 h.localize(ctx, "Logout"),
		"AdminModuleBruteForce":            h.localize(ctx, "Brute Force"),
		"AdminModuleClickHouse":            h.localize(ctx, "ClickHouse Runtime"),
		"AdminModuleHookTester":            h.localize(ctx, "Hook Tester"),
		"AdminBruteForceTitle":             h.localize(ctx, "Brute Force"),
		"AdminBruteForceHint":              h.localize(ctx, "Inspect and clear blocked IPs or accounts."),
		"AdminBruteForceTabIPs":            h.localize(ctx, "IP Addresses"),
		"AdminBruteForceTabAccounts":       h.localize(ctx, "Accounts"),
		"AdminBruteForceSearch":            h.localize(ctx, "Search"),
		"AdminBruteForceSearchPlaceholder": h.localize(ctx, "Search by IP, account or protocol"),
		"AdminBruteForceRefresh":           h.localize(ctx, "Refresh"),
		"AdminBruteForceFreeIP":            h.localize(ctx, "Free IP"),
		"AdminBruteForceFreeUser":          h.localize(ctx, "Free User"),
		"AdminClickHouseTitle":             h.localize(ctx, "ClickHouse Runtime"),
		"AdminClickHouseHint":              h.localize(ctx, "Query internal runtime hooks with server-side pagination."),
		"AdminClickHouseAction":            h.localize(ctx, "Action"),
		"AdminClickHouseStatus":            h.localize(ctx, "Status"),
		"AdminClickHouseFilter":            h.localize(ctx, "Filter"),
		"AdminClickHouseSearchPlaceholder": h.localize(ctx, "Search in result rows"),
		"AdminClickHouseRun":               h.localize(ctx, "Run Query"),
		"AdminClickHouseMap":               h.localize(ctx, "Geo Map"),
		"AdminClickHouseCountries":         h.localize(ctx, "Countries"),
		"AdminClickHouseResults":           h.localize(ctx, "Results"),
		"AdminHookTesterTitle":             h.localize(ctx, "Hook Tester"),
		"AdminHookTesterHint":              h.localize(ctx, "Send internal requests to /api/v1/custom/*hook with preview-limited response."),
		"AdminHookTesterMethod":            h.localize(ctx, "Method"),
		"AdminHookTesterEndpointPath":      h.localize(ctx, "Endpoint Path"),
		"AdminHookTesterQuery":             h.localize(ctx, "Query Params (JSON object)"),
		"AdminHookTesterHeaders":           h.localize(ctx, "Headers (JSON object)"),
		"AdminHookTesterContentType":       h.localize(ctx, "Content-Type"),
		"AdminHookTesterBody":              h.localize(ctx, "Body"),
		"AdminHookTesterSend":              h.localize(ctx, "Send Request"),
		"AdminHookTesterReset":             h.localize(ctx, "Reset"),
		"AdminHookTesterResponse":          h.localize(ctx, "Response"),
		"AdminHookTesterHTTPStatus":        h.localize(ctx, "HTTP Status"),
		"AdminHookTesterResponseHeaders":   h.localize(ctx, "Response Headers"),
		"AdminHookTesterResponseBody":      h.localize(ctx, "Response Body (preview-limited)"),
		"AdminTableColumnUsername":         h.localize(ctx, "Username"),
		"AdminTableColumnAccount":          h.localize(ctx, "Account"),
		"AdminTableColumnIP":               h.localize(ctx, "IP Address"),
		"AdminTableColumnProtocol":         h.localize(ctx, "Protocol"),
		"AdminTableColumnStatus":           h.localize(ctx, "Status"),
		"AdminTableColumnTimestamp":        h.localize(ctx, "Timestamp"),
		"AdminNoData":                      h.localize(ctx, "No data yet."),
	}
}

func (h *Handler) localizedModules(ctx *gin.Context) []localizedModule {
	result := make([]localizedModule, 0, len(h.modules))

	for _, module := range h.modules {
		result = append(result, localizedModule{
			ID:    module.ID,
			Title: h.localize(ctx, moduleTitle(module.ID, module.Title)),
			Route: module.Route,
		})
	}

	return result
}

func moduleTitle(id, fallback string) string {
	switch id {
	case "bruteforce":
		return "Brute Force"
	case "clickhouse":
		return "ClickHouse Runtime"
	case "hooktester":
		return "Hook Tester"
	default:
		return fallback
	}
}

func (h *Handler) localize(ctx *gin.Context, message string) string {
	cfg := h.getConfig()
	if h == nil || h.deps == nil || h.deps.Logger == nil {
		return message
	}

	return frontend.GetLocalized(ctx, cfg, h.deps.Logger, message)
}

func (h *Handler) getConfig() config.File {
	if h == nil || h.deps == nil {
		return nil
	}

	return h.deps.Cfg
}

func (h *Handler) getEnv() config.Environment {
	if h == nil || h.deps == nil {
		return nil
	}

	return h.deps.Env
}

type unimplementedBruteForceService struct{}

func (unimplementedBruteForceService) List(ctx *gin.Context) {
	ctx.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (unimplementedBruteForceService) FreeIP(ctx *gin.Context) {
	ctx.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (unimplementedBruteForceService) FreeUser(ctx *gin.Context) {
	ctx.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

type coreBruteForceService struct {
	listHandler  gin.HandlerFunc
	flushHandler gin.HandlerFunc
	userHandler  gin.HandlerFunc
}

func newCoreBruteForceService(deps *handlerdeps.Deps) BruteForceService {
	if deps == nil || deps.Cfg == nil || deps.Logger == nil || deps.Redis == nil {
		return unimplementedBruteForceService{}
	}

	var flushOptions []core.TokenFlusher
	if deps.TokenFlusher != nil {
		flushOptions = append(flushOptions, deps.TokenFlusher)
	}

	return &coreBruteForceService{
		listHandler:  core.NewBruteForceListHandler(deps.Cfg, deps.Logger, deps.Redis),
		flushHandler: core.NewBruteForceFlushHandler(deps.Cfg, deps.Logger, deps.Redis),
		userHandler:  core.NewUserFlushHandler(deps.Cfg, deps.Logger, deps.Redis, flushOptions...),
	}
}

func (s *coreBruteForceService) List(ctx *gin.Context) {
	s.listHandler(ctx)
}

func (s *coreBruteForceService) FreeIP(ctx *gin.Context) {
	s.flushHandler(ctx)
}

func (s *coreBruteForceService) FreeUser(ctx *gin.Context) {
	s.userHandler(ctx)
}

type unimplementedClickhouseService struct{}

func (unimplementedClickhouseService) Query(_ *gin.Context) (any, error) {
	return gin.H{"error": "not implemented"}, nil
}

type defaultClickhouseService struct {
	handler gin.HandlerFunc
}

func newDefaultClickhouseService(deps *handlerdeps.Deps, validator oidcbearer.TokenValidator) ClickhouseService {
	if deps == nil || deps.CfgProvider == nil || deps.Logger == nil || deps.Redis == nil {
		return unimplementedClickhouseService{}
	}

	return &defaultClickhouseService{
		handler: custom.CustomRequestHandler(deps.CfgProvider, deps.Logger, deps.Redis, validator),
	}
}

func (s *defaultClickhouseService) Query(ctx *gin.Context) (any, error) {
	hookPath := normalizeClickhouseHookPath(ctx.Query("endpoint_path"))
	if hookPath == "" {
		return nil, fmt.Errorf("invalid endpoint_path")
	}

	page, pageSize := parsePageAndSize(ctx.Query("page"), ctx.Query("page_size"))
	offset := (page - 1) * pageSize
	limit := pageSize + 1

	params := projectClickhouseQueryParams(ctx.Request.URL.Query(), offset, limit)

	req := ctx.Request.Clone(ctx.Request.Context())
	req.Method = http.MethodGet
	req.URL = &url.URL{
		Path:     "/api/v1/custom" + hookPath,
		RawQuery: params.Encode(),
	}
	req.Header = ctx.Request.Header.Clone()

	rec := httptest.NewRecorder()
	child, _ := gin.CreateTestContext(rec)
	child.Request = req
	child.Params = gin.Params{{Key: "hook", Value: hookPath}}
	child.Set(definitions.CtxGUIDKey, ctx.GetString(definitions.CtxGUIDKey))

	if claims, ok := ctx.Get(definitions.CtxOIDCClaimsKey); ok {
		child.Set(definitions.CtxOIDCClaimsKey, claims)
	}

	s.handler(child)

	if rec.Code >= http.StatusBadRequest {
		return nil, fmt.Errorf("clickhouse hook failed with status %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	var payload any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		return nil, fmt.Errorf("unable to decode hook response: %w", err)
	}

	rows := extractClickhouseRows(payload)
	hasMore := len(rows) > pageSize
	if hasMore {
		rows = rows[:pageSize]
	}

	return gin.H{
		"page":          page,
		"page_size":     pageSize,
		"has_more":      hasMore,
		"offset":        offset,
		"limit":         pageSize,
		"rows":          rows,
		"hook_response": payload,
	}, nil
}

type unimplementedHookTesterService struct{}

func (unimplementedHookTesterService) Send(_ *gin.Context) (any, error) {
	return gin.H{"error": "not implemented"}, nil
}

type defaultHookTesterService struct {
	handler gin.HandlerFunc
}

type hookTesterRequest struct {
	Method      string         `json:"method"`
	Endpoint    string         `json:"endpoint_path"`
	Query       map[string]any `json:"query"`
	Headers     map[string]any `json:"headers"`
	ContentType string         `json:"content_type"`
	Body        string         `json:"body"`
}

func newDefaultHookTesterService(deps *handlerdeps.Deps, validator oidcbearer.TokenValidator) HookTesterService {
	if deps == nil || deps.CfgProvider == nil || deps.Logger == nil || deps.Redis == nil {
		return unimplementedHookTesterService{}
	}

	return &defaultHookTesterService{
		handler: custom.CustomRequestHandler(deps.CfgProvider, deps.Logger, deps.Redis, validator),
	}
}

func (s *defaultHookTesterService) Send(ctx *gin.Context) (any, error) {
	requestSpec, err := decodeHookTesterRequest(ctx)
	if err != nil {
		return nil, err
	}

	method, err := normalizeHookTesterMethod(requestSpec.Method)
	if err != nil {
		return nil, err
	}

	hookPath, err := normalizeHookTesterEndpointPath(requestSpec.Endpoint)
	if err != nil {
		return nil, err
	}

	requestBody := []byte(requestSpec.Body)
	if len(requestBody) > hookTesterMaxRequestBodyBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", hookTesterMaxRequestBodyBytes)
	}

	query := convertObjectToQueryValues(requestSpec.Query)

	headers, err := normalizeHookTesterHeaders(requestSpec.Headers)
	if err != nil {
		return nil, err
	}

	if contentType := strings.TrimSpace(requestSpec.ContentType); contentType != "" {
		headers.Set("Content-Type", contentType)
	}

	rec, req := executeHookTesterRequest(ctx, s.handler, method, hookPath, query, headers, requestBody)

	return buildHookTesterResponse(rec, req), nil
}

func withBruteForceFallback(deps *handlerdeps.Deps, service BruteForceService) BruteForceService {
	if service == nil {
		return newCoreBruteForceService(deps)
	}

	return service
}

func withClickhouseFallback(deps *handlerdeps.Deps, validator oidcbearer.TokenValidator, service ClickhouseService) ClickhouseService {
	if service == nil {
		return newDefaultClickhouseService(deps, validator)
	}

	return service
}

func withHookFallback(deps *handlerdeps.Deps, validator oidcbearer.TokenValidator, service HookTesterService) HookTesterService {
	if service == nil {
		return newDefaultHookTesterService(deps, validator)
	}

	return service
}

func normalizeClickhouseHookPath(raw string) string {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "/hooks/clickhouse-query"
	}

	path = strings.TrimPrefix(path, "/api/v1")
	path = strings.TrimPrefix(path, "/custom")
	path = strings.TrimSpace(path)

	if path == "" {
		return "/hooks/clickhouse-query"
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return path
}

func parsePageAndSize(pageRaw, pageSizeRaw string) (int, int) {
	page := 1
	pageSize := 25

	if value, err := strconv.Atoi(strings.TrimSpace(pageRaw)); err == nil && value > 0 {
		page = value
	}

	if value, err := strconv.Atoi(strings.TrimSpace(pageSizeRaw)); err == nil {
		switch value {
		case 10, 25, 50, 100:
			pageSize = value
		}
	}

	return page, pageSize
}

func projectClickhouseQueryParams(in url.Values, offset, limit int) url.Values {
	out := url.Values{}
	allowed := []string{
		"action",
		"username",
		"account",
		"ip",
		"sql",
		"status",
		"search",
		"filter",
		"ts_start",
		"ts_end",
		"tz",
	}

	for _, key := range allowed {
		value := strings.TrimSpace(in.Get(key))
		if value != "" {
			out.Set(key, value)
		}
	}

	out.Set("offset", strconv.Itoa(offset))
	out.Set("limit", strconv.Itoa(limit))

	return out
}

func extractClickhouseRows(payload any) []map[string]any {
	root, ok := payload.(map[string]any)
	if !ok {
		return nil
	}

	if clickhouse, ok := root["clickhouse"].(map[string]any); ok {
		if rows := rowsFromDataNode(clickhouse["query_result"]); rows != nil {
			return rows
		}

		if rows := rowsFromDataNode(clickhouse["raw"]); rows != nil {
			return rows
		}
	}

	if rows := rowsFromDataNode(root["query_result"]); rows != nil {
		return rows
	}

	if rows := rowsFromDataNode(root["raw"]); rows != nil {
		return rows
	}

	return nil
}

func rowsFromDataNode(node any) []map[string]any {
	switch value := node.(type) {
	case map[string]any:
		if data, ok := value["data"].([]any); ok {
			return convertRows(data)
		}
	case string:
		var raw map[string]any
		if err := json.Unmarshal([]byte(value), &raw); err != nil {
			return nil
		}

		if data, ok := raw["data"].([]any); ok {
			return convertRows(data)
		}
	}

	return nil
}

func convertRows(data []any) []map[string]any {
	result := make([]map[string]any, 0, len(data))

	for _, row := range data {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}

		result = append(result, rowMap)
	}

	return result
}

func decodeHookTesterRequest(ctx *gin.Context) (*hookTesterRequest, error) {
	rawPayload, err := io.ReadAll(io.LimitReader(ctx.Request.Body, hookTesterMaxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("unable to read request: %w", err)
	}

	if len(rawPayload) == 0 {
		return nil, fmt.Errorf("request body is required")
	}

	if len(rawPayload) > hookTesterMaxEnvelopeBytes {
		return nil, fmt.Errorf("request exceeds %d bytes", hookTesterMaxEnvelopeBytes)
	}

	requestSpec := &hookTesterRequest{}
	if err = json.Unmarshal(rawPayload, requestSpec); err != nil {
		return nil, fmt.Errorf("invalid request payload: %w", err)
	}

	return requestSpec, nil
}

func normalizeHookTesterEndpointPath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", fmt.Errorf("endpoint_path is required")
	}

	path = strings.TrimPrefix(path, "/api/v1")
	path = strings.TrimPrefix(path, "/custom")
	path = strings.TrimSpace(path)

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	cleaned := pathpkg.Clean(path)
	if cleaned == "." || cleaned == "/" || cleaned == "/hooks" {
		return "", fmt.Errorf("endpoint_path must target /hooks/*")
	}

	if !strings.HasPrefix(cleaned, "/hooks/") {
		return "", fmt.Errorf("endpoint_path must target /hooks/*")
	}

	return cleaned, nil
}

func normalizeHookTesterMethod(raw string) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(raw))
	if method == "" {
		method = http.MethodPost
	}

	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method, nil
	default:
		return "", fmt.Errorf("unsupported method %q", method)
	}
}

func convertObjectToQueryValues(values map[string]any) url.Values {
	result := url.Values{}

	for key, value := range values {
		normalizedKey := strings.TrimSpace(key)
		if normalizedKey == "" {
			continue
		}

		normalizedValue := strings.TrimSpace(fmt.Sprint(value))
		if normalizedValue == "" {
			continue
		}

		result.Set(normalizedKey, normalizedValue)
	}

	return result
}

func normalizeHookTesterHeaders(values map[string]any) (http.Header, error) {
	result := make(http.Header)
	forbidden := map[string]struct{}{
		"Authorization":       {},
		"Connection":          {},
		"Content-Length":      {},
		"Cookie":              {},
		"Host":                {},
		"Proxy-Connection":    {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
		"Upgrade":             {},
	}

	for key, value := range values {
		normalizedKey := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if normalizedKey == "" {
			continue
		}

		if _, blocked := forbidden[normalizedKey]; blocked {
			return nil, fmt.Errorf("header %q is not allowed", normalizedKey)
		}

		normalizedValue := strings.TrimSpace(fmt.Sprint(value))
		if normalizedValue == "" {
			continue
		}

		if strings.ContainsAny(normalizedValue, "\r\n") {
			return nil, fmt.Errorf("header %q contains invalid characters", normalizedKey)
		}

		result.Set(normalizedKey, normalizedValue)
	}

	return result, nil
}

func flattenHeader(header http.Header) map[string]string {
	result := make(map[string]string, len(header))

	for key, values := range header {
		if len(values) == 0 {
			continue
		}

		result[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	return result
}

func executeHookTesterRequest(
	ctx *gin.Context,
	handler gin.HandlerFunc,
	method, hookPath string,
	query url.Values,
	headers http.Header,
	requestBody []byte,
) (*httptest.ResponseRecorder, *http.Request) {
	req := ctx.Request.Clone(ctx.Request.Context())
	req.Method = method
	req.URL = &url.URL{
		Path:     "/api/v1/custom" + hookPath,
		RawQuery: query.Encode(),
	}
	req.Header = headers.Clone()
	req.Body = io.NopCloser(bytes.NewReader(requestBody))
	req.ContentLength = int64(len(requestBody))

	rec := httptest.NewRecorder()
	child, _ := gin.CreateTestContext(rec)
	child.Request = req
	child.Params = gin.Params{{Key: "hook", Value: hookPath}}
	child.Set(definitions.CtxGUIDKey, ctx.GetString(definitions.CtxGUIDKey))

	if claims, ok := ctx.Get(definitions.CtxOIDCClaimsKey); ok {
		child.Set(definitions.CtxOIDCClaimsKey, claims)
	}

	handler(child)

	return rec, req
}

func buildHookTesterResponse(rec *httptest.ResponseRecorder, req *http.Request) gin.H {
	responseBody := rec.Body.Bytes()
	previewBody := responseBody
	isTruncated := false

	if len(responseBody) > hookTesterMaxResponsePreviewBytes {
		previewBody = responseBody[:hookTesterMaxResponsePreviewBytes]
		isTruncated = true
	}

	return gin.H{
		"status":                  rec.Code,
		"response_headers":        flattenHeader(rec.Header()),
		"request_headers":         flattenHeader(req.Header),
		"response_body":           string(previewBody),
		"response_body_bytes":     len(responseBody),
		"response_body_truncated": isTruncated,
		"response_content_type":   rec.Header().Get("Content-Type"),
	}
}
