// Copyright (C) 2024 Christian Rößner
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
	"encoding/base64"
	stderrors "errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	corelang "github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/frontend"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/v3/server/middleware/lua"
	"github.com/croessner/nauthilus/v3/server/middleware/securityheaders"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// FrontendHandler handles general IDP frontend pages like login and consent.
type FrontendHandler struct {
	deps        *deps.Deps
	mfa         idp.MFAProvider
	deviceStore idp.DeviceCodeStore
	tracer      monittrace.Tracer
}

type mfaAvailability struct {
	haveTOTP          bool
	haveWebAuthn      bool
	haveRecoveryCodes bool
	count             int
}

// NewFrontendHandler creates a new FrontendHandler.
func NewFrontendHandler(d *deps.Deps) *FrontendHandler {
	prefix := d.Cfg.GetServer().GetRedis().GetPrefix()

	return &FrontendHandler{
		deps:        d,
		mfa:         idp.NewMFAService(d),
		deviceStore: idp.NewRedisDeviceCodeStoreWithConfig(d.Redis, prefix, d.Cfg),
		tracer:      monittrace.New("nauthilus/idp/frontend"),
	}
}

func (h *FrontendHandler) getLoginURL(ctx *gin.Context) string {
	return h.appendQueryString(h.getLoginPath(ctx), ctx.Request.URL.RawQuery)
}

func (h *FrontendHandler) getLoginPath(ctx *gin.Context) string {
	// For device code flow, redirect back to the device verify page
	if mgr := cookie.GetManager(ctx); mgr != nil {
		if mgr.GetString(definitions.SessionKeyOIDCGrantType, "") == definitions.OIDCFlowDeviceCode {
			return h.deviceVerifyPath(ctx)
		}
	}

	lang := ctx.Param("languageTag")

	if lang != "" {
		return "/login/" + lang
	}

	return frontendLoginPath
}

// deviceVerifyPath returns the device verify page path with optional language tag.
func (h *FrontendHandler) deviceVerifyPath(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")

	if lang != "" {
		return frontendDeviceVerifyPath + "/" + lang
	}

	return frontendDeviceVerifyPath
}

func (h *FrontendHandler) getMFASelectPath(ctx *gin.Context) string {
	path := frontendMFASelectPath
	lang := ctx.Param("languageTag")

	if lang != "" {
		path += "/" + lang
	}

	return path
}

// localizedLoginPath appends the active language tag to browser login routes.
func localizedLoginPath(ctx *gin.Context, path string) string {
	lang := ctx.Param("languageTag")
	if lang == "" {
		return path
	}

	return path + "/" + lang
}

// localizedMFARootPath appends the active language tag to MFA self-service
// routes that have localized handler variants.
func localizedMFARootPath(ctx *gin.Context, path string) string {
	lang := ctx.Param("languageTag")
	if lang == "" {
		return path
	}

	return path + "/" + lang
}

// unlocalizedMFARootPath removes the active language suffix from localized MFA
// self-service request paths before route-sensitive comparisons.
func unlocalizedMFARootPath(ctx *gin.Context, path string) string {
	lang := ctx.Param("languageTag")
	if lang == "" {
		return path
	}

	return strings.TrimSuffix(path, "/"+lang)
}

func (h *FrontendHandler) appendQueryString(path string, query string) string {
	if query == "" {
		return path
	}

	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}

	return path + separator + query
}

// isValidIDPFlow checks if an active IDP flow exists in the secure session cookie.
// A valid IDP flow is either an OIDC request (authorization code or device code grant)
// or a SAML2 SSO request.
// The /login endpoint MUST NOT be accessed directly without a proper IDP flow.
// All flow state is stored in the encrypted cookie - no URL parameters are used for security.
func (h *FrontendHandler) isValidIDPFlow(ctx *gin.Context) bool {
	mgr := cookie.GetManager(ctx)
	if !hasActiveIDPFlow(mgr) {
		return false
	}

	flowType := mgr.GetString(definitions.SessionKeyIDPFlowType, "")
	switch flowType {
	case definitions.ProtoOIDC:
		return h.isValidOIDCFlow(mgr)
	case definitions.ProtoSAML:
		return h.isValidSAMLFlow(mgr)
	default:
		return false
	}
}

// hasActiveIDPFlow verifies that a secure session references an IDP flow.
func hasActiveIDPFlow(mgr cookie.Manager) bool {
	if mgr == nil {
		return false
	}

	return mgr.GetString(definitions.SessionKeyIDPFlowID, "") != ""
}

// isValidOIDCFlow verifies the required cookie state for an OIDC flow.
func (h *FrontendHandler) isValidOIDCFlow(mgr cookie.Manager) bool {
	grantType := mgr.GetString(definitions.SessionKeyOIDCGrantType, "")
	switch grantType {
	case definitions.OIDCFlowDeviceCode:
		return newOIDCDeviceFlowContext(mgr).DeviceCode() != "" &&
			mgr.GetString(definitions.SessionKeyIDPClientID, "") != ""
	case definitions.OIDCFlowAuthorizationCode:
		return newOIDCAuthorizeFlowContext(mgr).ResumeAuthorizeURL() != ""
	default:
		return false
	}
}

// isValidSAMLFlow verifies the required cookie state for a SAML flow.
func (h *FrontendHandler) isValidSAMLFlow(mgr cookie.Manager) bool {
	return newSAMLFlowContext(mgr).OriginalURL() != ""
}

// renderNoFlowError renders an error page when the /login endpoint is accessed without a valid IDP flow.
func (h *FrontendHandler) renderNoFlowError(ctx *gin.Context) {
	// Check if deps is available (may not be in tests)
	if h.deps == nil || h.deps.Cfg == nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			frontChannelLogoutTaskStatusError: "invalid_request",
			"message":                         "This login page can only be accessed through a valid OIDC or SAML2 authentication flow.",
		})

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Error")
	data["ErrorTitle"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid Request")
	data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "This login page can only be accessed through a valid OIDC or SAML2 authentication flow. Please use your application to initiate the login process.")

	ctx.HTML(http.StatusBadRequest, "idp_error.html", data)
}

// Register adds frontend routes to the router.
func (h *FrontendHandler) Register(router gin.IRouter) {
	registerFrontendStaticAssets(router, h.frontendAssetBase())
	registerIDPContextMiddleware(router)

	middlewares := h.newFrontendRouteMiddlewares()
	h.registerLoginRoutes(router, middlewares)
	h.registerAuthRoutes(router, middlewares)
	h.registerLoggedOutRoutes(router, middlewares)
}

type frontendRouteMiddlewares struct {
	security gin.HandlerFunc
	csrf     gin.HandlerFunc
	secure   gin.HandlerFunc
	i18n     gin.HandlerFunc
}

// frontendAssetBase resolves the directory that contains public frontend assets.
func (h *FrontendHandler) frontendAssetBase() string {
	staticPath := filepath.Clean(h.deps.Cfg.GetServer().Frontend.GetHTMLStaticContentPath())

	return frontendAssetBase(staticPath)
}

// frontendAssetBase returns the asset root for a configured template/static path.
func frontendAssetBase(staticPath string) string {
	if filepath.Base(staticPath) == "templates" {
		return filepath.Dir(staticPath)
	}

	return staticPath
}

// registerFrontendStaticAssets registers frontend CSS, JavaScript, image, and font assets.
func registerFrontendStaticAssets(router gin.IRouter, assetBase string) {
	router.StaticFile("/favicon.ico", filepath.Join(assetBase, "img", "favicon.ico"))
	router.Static("/static/css", filepath.Join(assetBase, "css"))
	router.Static("/static/js", filepath.Join(assetBase, "js"))
	router.Static("/static/img", filepath.Join(assetBase, "img"))
	router.Static("/static/fonts", filepath.Join(assetBase, "fonts"))
}

// registerIDPContextMiddleware annotates frontend requests with the IDP service context.
func registerIDPContextMiddleware(router gin.IRouter) {
	router.Use(idpServiceMiddleware(), mdlua.ContextMiddleware())
}

// idpServiceMiddleware marks the current request as an IDP frontend request.
func idpServiceMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
		ctx.Next()
	}
}

// newFrontendRouteMiddlewares builds the shared middleware chain for frontend pages.
func (h *FrontendHandler) newFrontendRouteMiddlewares() frontendRouteMiddlewares {
	return frontendRouteMiddlewares{
		security: securityheaders.New(securityheaders.MiddlewareConfig{Config: h.deps.Cfg}).Handler(),
		csrf:     csrf.New(),
		secure:   cookie.Middleware(h.frontendEncryptionSecret(), h.deps.Cfg, h.deps.Env),
		i18n:     i18n.WithLanguage(h.deps.Cfg, h.deps.Logger, h.deps.LangManager),
	}
}

// frontendEncryptionSecret copies the configured frontend cookie encryption secret.
func (h *FrontendHandler) frontendEncryptionSecret() []byte {
	var frontendSecret []byte

	h.deps.Cfg.GetServer().GetFrontend().GetEncryptionSecret().WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		frontendSecret = bytes.Clone(value)
	})

	return frontendSecret
}

// frontendRouteHandlers appends the endpoint handler to the standard frontend chain.
func frontendRouteHandlers(middlewares frontendRouteMiddlewares, handler gin.HandlerFunc) []gin.HandlerFunc {
	return []gin.HandlerFunc{middlewares.security, middlewares.csrf, middlewares.secure, middlewares.i18n, handler}
}

// frontendAuthRouteHandlers appends authentication middleware to the standard frontend chain.
func frontendAuthRouteHandlers(middlewares frontendRouteMiddlewares, auth gin.HandlerFunc) []gin.HandlerFunc {
	return []gin.HandlerFunc{middlewares.security, middlewares.csrf, middlewares.secure, middlewares.i18n, auth}
}

// frontendCookieFreeRouteHandlers builds a chain that does not write the secure session cookie.
func frontendCookieFreeRouteHandlers(middlewares frontendRouteMiddlewares, handler gin.HandlerFunc) []gin.HandlerFunc {
	return []gin.HandlerFunc{middlewares.security, middlewares.csrf, middlewares.i18n, handler}
}

// registerLoginRoutes registers login, MFA challenge, and recovery-code login routes.
func (h *FrontendHandler) registerLoginRoutes(router gin.IRouter, middlewares frontendRouteMiddlewares) {
	loginWebAuthnBegin := core.LoginWebAuthnBegin(h.deps.Auth())

	router.GET(frontendLoginPath, frontendRouteHandlers(middlewares, h.Login)...)
	router.GET("/login/:languageTag", frontendRouteHandlers(middlewares, h.Login)...)
	router.POST(frontendLoginPath, frontendRouteHandlers(middlewares, h.PostLogin)...)
	router.POST("/login/:languageTag", frontendRouteHandlers(middlewares, h.PostLogin)...)
	router.GET("/login/totp", frontendRouteHandlers(middlewares, h.LoginTOTP)...)
	router.GET("/login/totp/:languageTag", frontendRouteHandlers(middlewares, h.LoginTOTP)...)
	router.POST("/login/totp", frontendRouteHandlers(middlewares, h.PostLoginTOTP)...)
	router.POST("/login/totp/:languageTag", frontendRouteHandlers(middlewares, h.PostLoginTOTP)...)
	router.GET("/login/webauthn", frontendRouteHandlers(middlewares, h.LoginWebAuthn)...)
	router.GET("/login/webauthn/:languageTag", frontendRouteHandlers(middlewares, h.LoginWebAuthn)...)
	router.GET("/login/webauthn/begin", frontendRouteHandlers(middlewares, loginWebAuthnBegin)...)
	router.GET("/login/webauthn/begin/:languageTag", frontendRouteHandlers(middlewares, loginWebAuthnBegin)...)
	router.POST("/login/webauthn/finish", frontendRouteHandlers(middlewares, h.PostLoginWebAuthnFinish)...)
	router.POST("/login/webauthn/finish/:languageTag", frontendRouteHandlers(middlewares, h.PostLoginWebAuthnFinish)...)
	router.GET("/login/mfa", frontendRouteHandlers(middlewares, h.LoginMFASelect)...)
	router.GET("/login/mfa/:languageTag", frontendRouteHandlers(middlewares, h.LoginMFASelect)...)
	router.GET("/login/recovery", frontendRouteHandlers(middlewares, h.LoginRecovery)...)
	router.GET("/login/recovery/:languageTag", frontendRouteHandlers(middlewares, h.LoginRecovery)...)
	router.POST("/login/recovery", frontendRouteHandlers(middlewares, h.PostLoginRecovery)...)
	router.POST("/login/recovery/:languageTag", frontendRouteHandlers(middlewares, h.PostLoginRecovery)...)
}

// registerAuthRoutes registers protected MFA self-service routes.
func (h *FrontendHandler) registerAuthRoutes(router gin.IRouter, middlewares frontendRouteMiddlewares) {
	authGroup := router.Group(definitions.MFARoot, frontendAuthRouteHandlers(middlewares, h.AuthMiddleware())...)

	h.registerAuthHomeRoutes(authGroup)
	h.registerAuthTOTPRoutes(authGroup)
	h.registerAuthWebAuthnRoutes(authGroup)
	h.registerAuthRecoveryRoutes(authGroup)
	h.registerAuthContinuationRoutes(authGroup)
}

// registerAuthHomeRoutes registers the protected MFA home route.
func (h *FrontendHandler) registerAuthHomeRoutes(router gin.IRouter) {
	router.GET("/register/home", h.TwoFAHome)
	router.GET("/register/home/:languageTag", h.TwoFAHome)
}

// registerAuthTOTPRoutes registers protected TOTP management routes.
func (h *FrontendHandler) registerAuthTOTPRoutes(router gin.IRouter) {
	router.GET("/totp/register", h.RegisterTOTP)
	router.GET("/totp/register/:languageTag", h.RegisterTOTP)
	router.POST("/totp/register", h.PostRegisterTOTP)
	router.POST("/totp/register/:languageTag", h.PostRegisterTOTP)
	router.DELETE("/totp", h.DeleteTOTP)
	router.DELETE("/totp/:languageTag", h.DeleteTOTP)
}

// registerAuthWebAuthnRoutes registers protected WebAuthn management routes.
func (h *FrontendHandler) registerAuthWebAuthnRoutes(router gin.IRouter) {
	beginRegistration := core.BeginRegistration(h.deps.Auth())
	finishRegistration := core.FinishRegistration(h.deps.Auth())

	router.GET("/webauthn/register", h.RegisterWebAuthn)
	router.GET("/webauthn/register/:languageTag", h.RegisterWebAuthn)
	router.GET("/webauthn/register/begin", beginRegistration)
	router.GET("/webauthn/register/begin/:languageTag", beginRegistration)
	router.POST("/webauthn/register/finish", finishRegistration)
	router.POST("/webauthn/register/finish/:languageTag", finishRegistration)
	router.DELETE("/webauthn", h.DeleteWebAuthn)
	router.DELETE("/webauthn/:languageTag", h.DeleteWebAuthn)
	router.GET("/webauthn/devices", h.WebAuthnDevices)
	router.GET("/webauthn/devices/:languageTag", h.WebAuthnDevices)
	router.DELETE("/webauthn/device/:id", h.DeleteWebAuthnDevice)
	router.DELETE("/webauthn/device/:id/:languageTag", h.DeleteWebAuthnDevice)
	router.POST("/webauthn/device/:id/name", h.UpdateWebAuthnDeviceName)
	router.POST("/webauthn/device/:id/name/:languageTag", h.UpdateWebAuthnDeviceName)
}

// registerAuthRecoveryRoutes registers protected recovery-code management routes.
func (h *FrontendHandler) registerAuthRecoveryRoutes(router gin.IRouter) {
	router.GET("/recovery/register", h.RegisterRecoveryCodes)
	router.GET("/recovery/register/:languageTag", h.RegisterRecoveryCodes)
	router.POST("/recovery/register", h.PostRegisterRecoveryCodes)
	router.POST("/recovery/register/:languageTag", h.PostRegisterRecoveryCodes)
	router.POST("/recovery/register/save", h.SaveRecoveryCodes)
	router.POST("/recovery/register/save/:languageTag", h.SaveRecoveryCodes)
	router.POST("/recovery/generate", h.PostGenerateRecoveryCodes)
	router.POST("/recovery/generate/:languageTag", h.PostGenerateRecoveryCodes)
}

// registerAuthContinuationRoutes registers required-MFA continuation and cancel routes.
func (h *FrontendHandler) registerAuthContinuationRoutes(router gin.IRouter) {
	router.GET("/register/continue", h.ContinueRequiredMFARegistration)
	router.GET("/register/continue/:languageTag", h.ContinueRequiredMFARegistration)
	router.GET("/register/cancel", h.CancelRequiredMFARegistration)
	router.GET("/register/cancel/:languageTag", h.CancelRequiredMFARegistration)
}

// registerLoggedOutRoutes registers logout pages without secure session writes.
func (h *FrontendHandler) registerLoggedOutRoutes(router gin.IRouter, middlewares frontendRouteMiddlewares) {
	router.GET("/logged_out", frontendCookieFreeRouteHandlers(middlewares, h.LoggedOut)...)
	router.GET("/logged_out/:languageTag", frontendCookieFreeRouteHandlers(middlewares, h.LoggedOut)...)
}

// AuthMiddleware ensures the user is logged in for protected pages like 2FA Self-Service.
// Users must already have a valid session from a completed IDP flow.
// Direct access without a prior login redirects to an error page.
func (h *FrontendHandler) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		mgr := cookie.GetManager(ctx)
		account := ""

		if mgr != nil {
			account = mgr.GetString(definitions.SessionKeyAccount, "")
		}

		if account == "" {
			// User is not logged in - show error page instead of redirect to login.
			// The 2FA Self-Service pages are only accessible after a completed IDP flow.
			h.renderNoFlowError(ctx)
			ctx.Abort()

			return
		}

		ctx.Next()
	}
}

func (h *FrontendHandler) basePageData(ctx *gin.Context) gin.H {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)

	data["DevMode"] = h.deps.Env.GetDevMode()
	data["HXRequest"] = ctx.GetHeader("HX-Request") != ""

	return data
}

func (h *FrontendHandler) setLoginRememberData(ctx *gin.Context, data gin.H, oidcCID, samlEntityID string) {
	data["ShowRememberMe"] = h.shouldShowRememberMe(oidcCID, samlEntityID)
	data["RememberMeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Remember me")
}

// BasePageData returns the common data for all IDP frontend pages.
func BasePageData(ctx *gin.Context, cfg config.File, langManager corelang.Manager) gin.H {
	sessionData := basePageSessionDataFromContext(ctx)
	languageData := basePageLanguageDataFromContext(ctx, langManager)
	idpClientName := resolveIDPClientName(
		cfg,
		sessionData.flowType,
		sessionData.oidcClientID,
		sessionData.samlEntityID,
	)
	data := gin.H{
		templateDataLanguageTag:         languageData.tag,
		templateDataLanguageCurrentName: languageData.currentName,
		templateDataLanguagePassive: frontend.CreateLanguagePassive(
			ctx,
			languageData.path,
			languageData.availableTags,
			languageData.currentName,
		),
		"Username":                sessionData.username,
		templateDataCSPNonce:      securityheaders.NonceFromContext(ctx),
		templateDataConfirmTitle:  frontend.GetLocalized(ctx, cfg, nil, "Confirmation"),
		templateDataConfirmYes:    frontend.GetLocalized(ctx, cfg, nil, "Yes"),
		templateDataConfirmNo:     frontend.GetLocalized(ctx, cfg, nil, "Cancel"),
		"Logout":                  frontend.GetLocalized(ctx, cfg, nil, "Logout"),
		templateDataIDPClientName: idpClientName,
		"SelfServiceHomeEndpoint": localizedMFARootPath(ctx, definitions.MFARoot+"/register/home"),
	}

	setLegalLinksData(ctx, cfg, data)

	return data
}

type basePageSessionData struct {
	username     string
	flowType     string
	oidcClientID string
	samlEntityID string
}

type basePageLanguageData struct {
	availableTags []language.Tag
	tag           string
	currentName   string
	path          string
}

// basePageSessionDataFromContext extracts user and IDP client state from the secure session.
func basePageSessionDataFromContext(ctx *gin.Context) basePageSessionData {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return basePageSessionData{}
	}

	sessionData := basePageSessionData{
		username: mgr.GetString(definitions.SessionKeyAccount, ""),
		flowType: mgr.GetString(definitions.SessionKeyIDPFlowType, ""),
	}

	switch sessionData.flowType {
	case definitions.ProtoOIDC:
		sessionData.oidcClientID = mgr.GetString(definitions.SessionKeyIDPClientID, "")
	case definitions.ProtoSAML:
		sessionData.samlEntityID = mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")
	}

	return sessionData
}

// basePageLanguageDataFromContext resolves language display data for frontend templates.
func basePageLanguageDataFromContext(ctx *gin.Context, langManager corelang.Manager) basePageLanguageData {
	availableTags := languageTagsFromManager(langManager)
	lang := resolveBasePageLanguageTag(ctx)
	tag := language.Make(lang)
	currentName := cases.Title(tag, cases.NoLower).String(display.Self.Name(tag))

	return basePageLanguageData{
		availableTags: availableTags,
		tag:           lang,
		currentName:   currentName,
		path:          stripLanguageTagFromPath(ctx.Request.URL.Path, availableTags),
	}
}

// languageTagsFromManager returns the configured frontend language tags.
func languageTagsFromManager(langManager corelang.Manager) []language.Tag {
	if langManager == nil {
		return []language.Tag{}
	}

	return langManager.GetTags()
}

// resolveBasePageLanguageTag selects the URL, cookie, or default language tag.
func resolveBasePageLanguageTag(ctx *gin.Context) string {
	lang := strings.TrimSpace(ctx.Param("languageTag"))
	if lang != "" {
		return lang
	}

	if cookieLang, err := ctx.Cookie(definitions.LanguageCookieName); err == nil {
		lang = strings.TrimSpace(cookieLang)
	}

	if lang == "" {
		return frontendDefaultLanguageTag
	}

	return lang
}

// stripLanguageTagFromPath removes a trailing language segment from a template path.
func stripLanguageTagFromPath(path string, languageTags []language.Tag) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 1 {
		return path
	}

	lastPart := parts[len(parts)-1]

	for _, tag := range languageTags {
		base, _ := tag.Base()
		if base.String() == lastPart {
			return strings.Join(parts[:len(parts)-1], "/")
		}
	}

	return path
}

func setLegalLinksData(ctx *gin.Context, cfg config.File, data gin.H) {
	if cfg != nil {
		idpCfg := cfg.GetIDP()
		if idpCfg != nil {
			data["TermsOfServiceURL"] = idpCfg.TermsOfServiceURL
			data["PrivacyPolicyURL"] = idpCfg.PrivacyPolicyURL
			data["PasswordForgottenURL"] = idpCfg.PasswordForgottenURL
		}
	}

	data["LegalNoticeLabel"] = frontend.GetLocalized(ctx, cfg, nil, "Legal notice")
	data["PrivacyPolicyLabel"] = frontend.GetLocalized(ctx, cfg, nil, "Privacy policy")
	data["PasswordForgottenLabel"] = frontend.GetLocalized(ctx, cfg, nil, "Forgot password?")
}

func resolveIDPClientName(cfg config.File, flowType string, oidcClientID string, samlEntityID string) string {
	if flowType == definitions.ProtoOIDC && oidcClientID != "" {
		clients := cfg.GetIDP().OIDC.Clients
		for i := range clients {
			if clients[i].ClientID == oidcClientID {
				return clients[i].Name
			}
		}
	}

	if flowType == definitions.ProtoSAML && samlEntityID != "" {
		for _, sp := range cfg.GetIDP().SAML2.ServiceProviders {
			if sp.EntityID == samlEntityID {
				return sp.Name
			}
		}
	}

	return ""
}

// Login renders the modern login page.
// This endpoint is ONLY for IDP flows (OIDC/SAML2). Direct access without a proper flow is rejected.
// All flow state is read from the secure encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) Login(ctx *gin.Context) {
	if !h.isValidIDPFlow(ctx) {
		h.renderNoFlowError(ctx)

		return
	}

	mgr := cookie.GetManager(ctx)
	flowState := h.loginFlowState(mgr)

	if h.resumeExistingLoginSession(ctx, mgr) {
		return
	}

	if flowState.grantType == definitions.OIDCFlowDeviceCode {
		ctx.Redirect(http.StatusFound, h.deviceVerifyPath(ctx))

		return
	}

	if mgr != nil {
		mgr.Delete(definitions.SessionKeyMFAMulti)
	}

	h.renderLoginPage(ctx, mgr, flowState)
}

type loginFlowState struct {
	flowType     string
	grantType    string
	oidcCID      string
	samlEntityID string
}

// loginFlowState extracts flow identifiers used by the login page.
func (h *FrontendHandler) loginFlowState(mgr cookie.Manager) loginFlowState {
	if mgr == nil {
		return loginFlowState{}
	}

	oidcCID, samlEntityID := h.getFlowClientIdentifiers(mgr)

	flowType := mgr.GetString(definitions.SessionKeyIDPFlowType, "")
	if flowType == definitions.ProtoSAML && samlEntityID == "" {
		samlEntityID = definitions.ProtoSAML
	}

	return loginFlowState{
		flowType:     flowType,
		grantType:    mgr.GetString(definitions.SessionKeyOIDCGrantType, ""),
		oidcCID:      oidcCID,
		samlEntityID: samlEntityID,
	}
}

// resumeExistingLoginSession resumes the IDP flow for an already authenticated session.
func (h *FrontendHandler) resumeExistingLoginSession(ctx *gin.Context, mgr cookie.Manager) bool {
	if mgr == nil || mgr.GetString(definitions.SessionKeyAccount, "") == "" {
		return false
	}

	if h.redirectExistingSessionMFAAssurance(ctx, mgr) {
		return true
	}

	if !h.checkRequireMFARegistrationAndRedirect(ctx, mgr) {
		h.resumeIDPFlow(ctx, mgr)
	}

	return true
}

// webAuthnFinishResponse is returned to browser JavaScript after a successful
// WebAuthn login assertion. Redirect stays server-derived so the client never
// reconstructs IDP flow state.
type webAuthnFinishResponse struct {
	Redirect string `json:"redirect"`
}

// renderLoginPage renders the initial username/password login page.
func (h *FrontendHandler) renderLoginPage(ctx *gin.Context, mgr cookie.Manager, flowState loginFlowState) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IDP Login page request",
		"flow_type", flowState.flowType,
	)

	data := h.basePageData(ctx)
	h.applyLoginPageLabels(ctx, data)
	h.applyLoginErrorData(ctx, mgr, data)
	h.setLoginRememberData(ctx, data, flowState.oidcCID, flowState.samlEntityID)

	ctx.HTML(http.StatusOK, "idp_login.html", data)
}

// applyLoginPageLabels adds localized labels and endpoints for the login form.
func (h *FrontendHandler) applyLoginPageLabels(ctx *gin.Context, data gin.H) {
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
	data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address")
	data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	data["CSRFToken"] = csrf.Token(ctx)
	data["PostLoginEndpoint"] = ctx.Request.URL.Path
}

// applyLoginErrorData adds and clears a stored login error after MFA retry paths.
func (h *FrontendHandler) applyLoginErrorData(ctx *gin.Context, mgr cookie.Manager, data gin.H) {
	if mgr != nil {
		if loginError := mgr.GetString(definitions.SessionKeyLoginError, ""); loginError != "" {
			data["HaveError"] = true
			data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, loginError)

			mgr.Delete(definitions.SessionKeyLoginError)
			_ = mgr.Save(ctx)

			return
		}
	}

	data["HaveError"] = false
	data["ErrorMessage"] = ""
}

// deviceCodeNeedsConsent checks whether the device code flow requires user consent for the given client.
// It mirrors the consent logic from the authorization code grant: consent is needed when
// the client has not set skip_consent and the user has not previously consented in this session.
func (h *FrontendHandler) deviceCodeNeedsConsent(ctx *gin.Context, clientID string, requestedScopes []string) bool {
	idpInstance := idp.NewNauthilusIDP(h.deps)

	client, ok := idpInstance.FindClient(clientID)
	if !ok {
		return false
	}

	if client.SkipConsent {
		return false
	}

	mgr := cookie.GetManager(ctx)

	return !newOIDCAuthorizeFlowContext(mgr).HasClientConsent(clientID, requestedScopes)
}

// completeDeviceCodeFlow authorizes the device code and renders the success page.
// This is called after successful authentication (and MFA if required) in the device code flow.
func (h *FrontendHandler) completeDeviceCodeFlow(ctx *gin.Context, mgr cookie.Manager) {
	deviceCode, request, ok := h.deviceCodeRequestFromSession(ctx, mgr)
	if !ok {
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	if h.denyDeviceCodeAfterDelayedMFA(ctx, mgr, deviceCode, request) {
		return
	}

	if h.redirectDeviceCodeConsent(ctx, request) {
		return
	}

	idpInstance := idp.NewNauthilusIDP(h.deps)

	client, ok := h.deviceCodeClientOrDeny(ctx, mgr, deviceCode, request, idpInstance)
	if !ok {
		return
	}

	if !h.authorizeDeviceCodeRequest(ctx, mgr, deviceCode, request, idpInstance, client) {
		return
	}

	h.finishAuthorizedDeviceCodeFlow(ctx, mgr, request, client)
}

// deviceCodeRequestFromSession loads the device-code request referenced by session state.
func (h *FrontendHandler) deviceCodeRequestFromSession(
	ctx *gin.Context,
	mgr cookie.Manager,
) (string, *idp.DeviceCodeRequest, bool) {
	deviceCode := mgr.GetString(definitions.SessionKeyDeviceCode, "")
	if deviceCode == "" {
		return "", nil, false
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil || request == nil {
		return "", nil, false
	}

	return deviceCode, request, true
}

// denyDeviceCodeAfterDelayedMFA handles fail-latched device-code MFA completion.
func (h *FrontendHandler) denyDeviceCodeAfterDelayedMFA(
	ctx *gin.Context,
	mgr cookie.Manager,
	deviceCode string,
	request *idp.DeviceCodeRequest,
) bool {
	if !h.shouldDenyDeviceCodeAfterMFA(ctx, mgr) {
		return false
	}

	h.denyDeviceCodeAndAbort(ctx, mgr, deviceCode, request)
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code denied after delayed-response MFA completion",
		"client_id", request.ClientID,
		"user_code", request.UserCode,
	)

	renderDeviceCodeFailed(
		ctx,
		h.deps,
		renderStoredIDPAuthStatusBridgeMessage(ctx, h.deps, mgr, idpGenericInvalidLoginMessage),
	)

	return true
}

// denyDeviceCodeAndAbort marks the request denied and aborts the surrounding flow.
func (h *FrontendHandler) denyDeviceCodeAndAbort(
	ctx *gin.Context,
	mgr cookie.Manager,
	deviceCode string,
	request *idp.DeviceCodeRequest,
) {
	request.Status = idp.DeviceCodeStatusDenied
	_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)
	abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())
}

// redirectDeviceCodeConsent redirects to consent when the device flow still needs approval.
func (h *FrontendHandler) redirectDeviceCodeConsent(ctx *gin.Context, request *idp.DeviceCodeRequest) bool {
	if !h.deviceCodeNeedsConsent(ctx, request.ClientID, request.Scopes) {
		return false
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code flow requires consent (after MFA)",
		"client_id", request.ClientID,
	)

	ctx.Redirect(http.StatusFound, frontendDeviceConsentPathWithLanguage(ctx))

	return true
}

// frontendDeviceConsentPathWithLanguage returns the localized consent path when needed.
func frontendDeviceConsentPathWithLanguage(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")
	if lang == "" {
		return frontendDeviceConsentPath
	}

	return frontendDeviceConsentPath + "/" + lang
}

// deviceCodeClientOrDeny resolves the client or denies the device code on missing config.
func (h *FrontendHandler) deviceCodeClientOrDeny(
	ctx *gin.Context,
	mgr cookie.Manager,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	idpInstance *idp.NauthilusIDP,
) (*config.OIDCClient, bool) {
	client, ok := idpInstance.FindClient(request.ClientID)
	if !ok {
		h.denyDeviceCodeAndAbort(ctx, mgr, deviceCode, request)
		renderDeviceCodeFailed(ctx, h.deps, "Internal server error")

		return nil, false
	}

	return client, true
}

// authorizeDeviceCodeRequest populates claims and persists an authorized device-code request.
func (h *FrontendHandler) authorizeDeviceCodeRequest(
	ctx *gin.Context,
	mgr cookie.Manager,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	idpInstance *idp.NauthilusIDP,
	client *config.OIDCClient,
) bool {
	request.Status = idp.DeviceCodeStatusAuthorized
	request.UserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
	applyDeviceCodeMFASessionState(mgr, request)

	if err := hydrateDeviceRequestClaims(ctx, idpInstance, request, client, nil); err != nil {
		h.denyDeviceCodeAndAbort(ctx, mgr, deviceCode, request)

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code flow completion failed to hydrate claims",
			"client_id", request.ClientID,
			"user_id", request.UserID,
			"error", err,
		)

		renderDeviceCodeFailed(ctx, h.deps, "Internal server error")

		return false
	}

	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		ctx.Redirect(http.StatusFound, "/")

		return false
	}

	return true
}

// finishAuthorizedDeviceCodeFlow records consent, advances flow state, and renders success.
func (h *FrontendHandler) finishAuthorizedDeviceCodeFlow(
	ctx *gin.Context,
	mgr cookie.Manager,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
) {
	newOIDCAuthorizeFlowContext(mgr).AddClientConsent(request.ClientID, request.Scopes, consentTTLForClient(h.deps.Cfg, client))

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code authorized via MFA flow (consent skipped)",
		"client_id", request.ClientID,
		"user_id", request.UserID,
		"user_code", request.UserCode,
	)

	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepCallback)
	completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	renderDeviceCodeSuccess(ctx, h.deps)
}

// shouldDenyDeviceCodeAfterMFA checks whether a device-code flow should be denied
// because the original password authentication failed (delayed response case).
// Uses HMAC-verified auth result for default-deny behavior.
func (h *FrontendHandler) shouldDenyDeviceCodeAfterMFA(ctx *gin.Context, mgr cookie.Manager) bool {
	if mgr == nil {
		return false
	}

	username := mgr.GetString(definitions.SessionKeyUsername, "")
	if username == "" {
		return false
	}

	if h != nil && h.deps != nil {
		if flowAuthFailureLatched(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix()) {
			return true
		}
	}

	result, ok := cookie.VerifyAuthResult(mgr, username)
	if !ok {
		// HMAC verification failed or auth_result missing — deny to be safe.
		return mgr.HasKey(definitions.SessionKeyAuthResult)
	}

	return result == definitions.AuthResultFail
}

func (h *FrontendHandler) handleDeviceCodeDelayedAuthFailure(ctx *gin.Context, mgr cookie.Manager) bool {
	if mgr == nil || mgr.GetString(definitions.SessionKeyOIDCGrantType, "") != definitions.OIDCFlowDeviceCode {
		return false
	}

	deviceCode := mgr.GetString(definitions.SessionKeyDeviceCode, "")

	if deviceCode != "" {
		request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
		if err == nil && request != nil {
			request.Status = idp.DeviceCodeStatusDenied
			_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)
		}
	}

	abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())
	renderDeviceCodeFailed(
		ctx,
		h.deps,
		renderStoredIDPAuthStatusBridgeMessage(ctx, h.deps, mgr, idpGenericInvalidLoginMessage),
	)

	return true
}

// handleDelayedResponseFailure checks whether the original password authentication failed
// (delayed response case) and, if so, renders the login page with an error message.
// Returns true if the failure was handled (caller should return), false if auth was OK.
//
// Default-deny: if the HMAC verification fails, mgr is nil, or auth_result is missing,
// the login is rejected.
func (h *FrontendHandler) handleDelayedResponseFailure(ctx *gin.Context, sess *mfaSessionState, mfaMethod string) bool {
	if h != nil && h.deps != nil && sess != nil {
		if outcome, ok := getFlowAuthOutcome(ctx.Request.Context(), sess.mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix()); ok {
			if outcome == flowdomain.AuthOutcomeOK {
				return false
			}
		}
	}

	result, ok := cookie.VerifyAuthResult(sess.mgr, sess.username)
	if ok && result == definitions.AuthResultOK {
		return false
	}

	// Device code flow has its own failure path.
	if h.handleDeviceCodeDelayedAuthFailure(ctx, sess.mgr) {
		return true
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Delayed-response login rejected after MFA",
		"mfa_method", mfaMethod,
		"username", sess.username,
	)

	data := h.basePageData(ctx)
	h.applyDelayedLoginFailureData(ctx, sess, data)

	h.resetDelayedResponseFailureForRetry(ctx, sess.mgr)

	// Clean up MFA cookie state so the next login attempt starts fresh.
	CleanupMFAState(sess.mgr)

	ctx.HTML(http.StatusOK, "idp_login.html", data)

	return true
}

// applyDelayedLoginFailureData fills login-page data for fail-latched MFA completion.
func (h *FrontendHandler) applyDelayedLoginFailureData(ctx *gin.Context, sess *mfaSessionState, data gin.H) {
	h.applyLoginPageLabels(ctx, data)
	h.applyLoginMFAFallbackLabels(ctx, data)
	data["PostLoginEndpoint"] = localizedLoginEndpoint(ctx)
	data["HaveError"] = true
	data["ErrorMessage"] = renderStoredIDPAuthStatusBridgeMessage(ctx, h.deps, sess.mgr, idpGenericInvalidLoginMessage)

	h.setLoginRememberData(ctx, data, sess.oidcCID, sess.samlEntityID)
}

// applyLoginMFAFallbackLabels adds optional WebAuthn login labels to login pages.
func (h *FrontendHandler) applyLoginMFAFallbackLabels(ctx *gin.Context, data gin.H) {
	data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
	data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")
	data["WebAuthnLoginURL"] = h.getMFAURLFromCookie(ctx, "webauthn")
}

// localizedLoginEndpoint returns the localized login endpoint for retry posts.
func localizedLoginEndpoint(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")
	if lang == "" {
		return frontendLoginPath
	}

	return "/login/" + lang
}

func (h *FrontendHandler) resetDelayedResponseFailureForRetry(ctx *gin.Context, mgr cookie.Manager) bool {
	if ctx == nil {
		return false
	}

	var (
		redisClient rediscli.Client
		redisPrefix string
	)

	if h != nil && h.deps != nil {
		redisClient = h.deps.Redis
		if h.deps.Cfg != nil && h.deps.Cfg.GetServer() != nil {
			redisPrefix = h.deps.Cfg.GetServer().GetRedis().GetPrefix()
		}
	}

	return resetFlowAuthOutcomeForRetry(ctx.Request.Context(), mgr, redisClient, redisPrefix)
}

// renderPostLoginFailure renders the IDP login form with a generic authentication error.
func (h *FrontendHandler) renderPostLoginFailure(ctx *gin.Context, oidcCID string, samlEntityID string, message string) {
	data := h.basePageData(ctx)
	h.applyLoginPageLabels(ctx, data)
	h.applyLoginMFAFallbackLabels(ctx, data)
	data["HaveError"] = true
	data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, message)

	h.setLoginRememberData(ctx, data, oidcCID, samlEntityID)

	ctx.HTML(http.StatusOK, "idp_login.html", data)
}

// preAuthMFASessionOptions carries the identity and flow state required before MFA verification starts.
type preAuthMFASessionOptions struct {
	user          *backend.User
	factorUser    *backend.User
	username      string
	protocol      string
	authResult    definitions.AuthResult
	authOutcome   flowdomain.AuthOutcome
	factorRef     core.RemoteBackendRef
	rememberMeTTL int
	redisPrefix   string
	debugMessage  string
}

// storePreAuthMFASession stores the submitted login for factor checks and the canonical identity for finalization.
func (h *FrontendHandler) storePreAuthMFASession(ctx *gin.Context, mgr cookie.Manager, options preAuthMFASessionOptions) {
	if mgr == nil || options.user == nil {
		return
	}

	mgr.Set(definitions.SessionKeyUsername, options.username)
	core.StorePendingIDPMFAIdentity(mgr, options.user)
	core.StorePendingIDPMFAFactor(mgr, options.mfaFactorUser())
	core.StorePendingIDPMFAFactorRemoteBackendRef(mgr, options.factorRef)
	cookie.SetAuthResult(mgr, options.username, options.authResult)
	mgr.Set(definitions.SessionKeyProtocol, options.protocol)
	_ = setFlowAuthOutcome(ctx.Request.Context(), mgr, h.deps.Redis, options.redisPrefix, options.authOutcome)

	if options.rememberMeTTL > 0 {
		mgr.Set(definitions.SessionKeyRememberTTL, options.rememberMeTTL)
	}

	mgr.Debug(ctx, h.deps.Logger, options.debugMessage)
}

// mfaFactorUser returns the account whose second factor should be verified.
func (o preAuthMFASessionOptions) mfaFactorUser() *backend.User {
	if o.factorUser != nil {
		return o.factorUser
	}

	return o.user
}

// parseSubmittedMasterUser resolves the target and master account from a submitted login.
func (h *FrontendHandler) parseSubmittedMasterUser(submittedUsername string, targetUser *backend.User) (string, string, bool) {
	if h != nil && h.deps != nil && h.deps.Cfg != nil && h.deps.Cfg.GetServer() != nil {
		masterUser := h.deps.Cfg.GetServer().GetMasterUser()
		if masterUser.IsEnabled() {
			return config.ParseMasterUserLogin(submittedUsername, masterUser.GetUserFormat())
		}
	}

	if targetUser == nil || targetUser.Name == "" || submittedUsername == targetUser.Name {
		return "", "", false
	}

	targetUsername, masterUsername, ok := config.ParseMasterUserLogin(submittedUsername, config.DefaultMasterUserFormat)
	if !ok || targetUsername != targetUser.Name {
		return "", "", false
	}

	return targetUsername, masterUsername, true
}

// resolveMFAFactorUser loads the Master-User account when the submitted login uses master mode.
func (h *FrontendHandler) resolveMFAFactorUser(
	ctx *gin.Context,
	idpInstance *idp.NauthilusIDP,
	submittedUsername string,
	targetUser *backend.User,
	oidcCID string,
	samlEntityID string,
) (*backend.User, bool, core.RemoteBackendRef, error) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || h.deps.Cfg.GetServer() == nil {
		return targetUser, false, core.RemoteBackendRef{}, nil
	}

	_, masterUsername, ok := h.parseSubmittedMasterUser(submittedUsername, targetUser)
	if !ok {
		return targetUser, false, core.RemoteBackendRef{}, nil
	}

	if idpInstance == nil {
		return nil, true, core.RemoteBackendRef{}, stderrors.New("missing IDP instance")
	}

	mgr := cookie.GetManager(ctx)
	targetRef, haveTargetRef := core.RemoteBackendRefFromSession(mgr)

	if mgr != nil {
		core.ClearRemoteBackendRef(mgr)

		defer func() {
			if haveTargetRef {
				core.StoreRemoteBackendRef(mgr, targetRef)

				return
			}

			core.ClearRemoteBackendRef(mgr)
		}()
	}

	factorUser, err := idpInstance.GetUserByUsername(ctx, masterUsername, oidcCID, samlEntityID)
	if err != nil {
		return nil, true, core.RemoteBackendRef{}, err
	}

	factorRef, _ := core.RemoteBackendRefFromSession(mgr)

	return factorUser, true, factorRef, nil
}

// postLoginFlowContext carries IDP flow state required for login.
type postLoginFlowContext struct {
	mgr          cookie.Manager
	flowType     string
	oidcCID      string
	samlEntityID string
	protocol     string
	redisPrefix  string
}

// postLoginCredentials carries submitted login credentials.
type postLoginCredentials struct {
	username      string
	password      string
	rememberMeTTL int
}

// postLoginMFAState carries resolved MFA information for login.
type postLoginMFAState struct {
	user         *backend.User
	factorUser   *backend.User
	factorRef    core.RemoteBackendRef
	availability mfaAvailability
}

// readPostLoginFlowContext reads flow identifiers from the encrypted session.
func (h *FrontendHandler) readPostLoginFlowContext(ctx *gin.Context) postLoginFlowContext {
	context := postLoginFlowContext{
		mgr:         cookie.GetManager(ctx),
		protocol:    definitions.ProtoIDP,
		redisPrefix: h.deps.Cfg.GetServer().GetRedis().GetPrefix(),
	}
	if context.mgr == nil {
		return context
	}

	context.flowType = context.mgr.GetString(definitions.SessionKeyIDPFlowType, "")
	switch context.flowType {
	case definitions.ProtoOIDC:
		context.oidcCID = context.mgr.GetString(definitions.SessionKeyIDPClientID, "")
		context.protocol = definitions.ProtoOIDC
	case definitions.ProtoSAML:
		context.samlEntityID = context.mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")
		if context.samlEntityID == "" {
			context.samlEntityID = definitions.ProtoSAML
		}

		context.protocol = definitions.ProtoSAML
	}

	return context
}

// isDeviceCodeLoginFlow reports whether login must continue via device verification.
func (context postLoginFlowContext) isDeviceCodeLoginFlow() bool {
	return context.flowType == definitions.ProtoOIDC &&
		context.mgr != nil &&
		context.mgr.GetString(definitions.SessionKeyOIDCGrantType, "") == definitions.OIDCFlowDeviceCode
}

// readPostLoginCredentials reads submitted credentials and remember-me settings.
func (h *FrontendHandler) readPostLoginCredentials(ctx *gin.Context, flowContext postLoginFlowContext) postLoginCredentials {
	credentials := postLoginCredentials{
		username: ctx.PostForm("username"),
		password: ctx.PostForm("password"),
	}
	if ctx.PostForm("remember_me") == "on" {
		credentials.rememberMeTTL = int(h.getRememberMeTTL(flowContext.oidcCID, flowContext.samlEntityID).Seconds())
	}

	return credentials
}

// logPostLoginAttempt records the incoming login attempt.
func (h *FrontendHandler) logPostLoginAttempt(ctx *gin.Context, flowContext postLoginFlowContext, credentials postLoginCredentials) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IDP Login attempt",
		"username", credentials.username,
		"flow_type", flowContext.flowType,
	)
}

// renderDetailedPostLoginFailure renders login failure with mapped auth status.
func (h *FrontendHandler) renderDetailedPostLoginFailure(ctx *gin.Context, flowContext postLoginFlowContext, err error) {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
	data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address")
	data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
	data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")
	data["WebAuthnLoginURL"] = h.getMFAURLFromCookie(ctx, "webauthn")
	data["CSRFToken"] = csrf.Token(ctx)
	data["PostLoginEndpoint"] = ctx.Request.URL.Path
	data["HaveError"] = true
	data["ErrorMessage"] = renderIDPAuthFailureMessage(ctx, h.deps, err, idpGenericInvalidLoginMessage)

	h.setLoginRememberData(ctx, data, flowContext.oidcCID, flowContext.samlEntityID)
	ctx.HTML(http.StatusOK, "idp_login.html", data)
}

// delayedPostLoginMFAState resolves MFA state for delayed-response failures.
func (h *FrontendHandler) delayedPostLoginMFAState(
	ctx *gin.Context,
	sp trace.Span,
	idpInstance *idp.NauthilusIDP,
	flowContext postLoginFlowContext,
	credentials postLoginCredentials,
	err error,
) (postLoginMFAState, bool) {
	state := postLoginMFAState{}
	if !idpAuthFailureAllowsDelayedResponse(err) || !idpInstance.IsDelayedResponse(flowContext.oidcCID, flowContext.samlEntityID) {
		return state, false
	}

	user, _ := idpInstance.GetUserByUsername(ctx, credentials.username, flowContext.oidcCID, flowContext.samlEntityID)
	if user == nil {
		return state, false
	}

	factorUser, _, factorRef, factorErr := h.resolveMFAFactorUser(ctx, idpInstance, credentials.username, user, flowContext.oidcCID, flowContext.samlEntityID)
	if factorErr != nil {
		sp.RecordError(factorErr)

		factorUser = nil
	}

	state.user = user
	state.factorUser = factorUser
	state.factorRef = factorRef
	state.availability = h.getMFAAvailabilityWithBackendRef(ctx, factorUser, flowContext.protocol, flowContext.mgr, factorRef)

	return state, state.availability.count > 0
}

// redirectPostLoginMFA stores pre-auth state and redirects to MFA.
func (h *FrontendHandler) redirectPostLoginMFA(
	ctx *gin.Context,
	flowContext postLoginFlowContext,
	credentials postLoginCredentials,
	mfaState postLoginMFAState,
	authResult definitions.AuthResult,
	authOutcome flowdomain.AuthOutcome,
	debugMessage string,
	advance bool,
) {
	if flowContext.mgr != nil {
		h.storePreAuthMFASession(ctx, flowContext.mgr, preAuthMFASessionOptions{
			user:          mfaState.user,
			factorUser:    mfaState.factorUser,
			username:      credentials.username,
			protocol:      flowContext.protocol,
			authResult:    authResult,
			authOutcome:   authOutcome,
			factorRef:     mfaState.factorRef,
			rememberMeTTL: credentials.rememberMeTTL,
			redisPrefix:   flowContext.redisPrefix,
			debugMessage:  debugMessage,
		})
	}

	if advance && flowContext.mgr != nil {
		advanceFlow(ctx.Request.Context(), flowContext.mgr, h.deps.Redis, flowContext.redisPrefix, flowdomain.FlowStepLogin)
		advanceFlow(ctx.Request.Context(), flowContext.mgr, h.deps.Redis, flowContext.redisPrefix, flowdomain.FlowStepMFA)
	}

	if redirectURL, ok := h.getMFARedirectURLFromAvailability(mfaState.availability); ok {
		ctx.Redirect(http.StatusFound, redirectURL)

		return
	}

	ctx.Redirect(http.StatusFound, "/login/mfa")
}

// handlePostLoginAuthFailure handles failed password auth including delayed response.
func (h *FrontendHandler) handlePostLoginAuthFailure(
	ctx *gin.Context,
	sp trace.Span,
	idpInstance *idp.NauthilusIDP,
	flowContext postLoginFlowContext,
	credentials postLoginCredentials,
	err error,
) {
	sp.RecordError(err)
	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

	mfaState, ok := h.delayedPostLoginMFAState(ctx, sp, idpInstance, flowContext, credentials, err)
	if ok {
		if flowContext.mgr != nil {
			storeIDPAuthStatusBridgeFromError(flowContext.mgr, err)
		}

		h.redirectPostLoginMFA(
			ctx,
			flowContext,
			credentials,
			mfaState,
			definitions.AuthResultFail,
			flowdomain.AuthOutcomeFailLatched,
			"MFA required - pre-auth session data stored (delayed response)",
			false,
		)

		return
	}

	h.renderDetailedPostLoginFailure(ctx, flowContext, err)
}

// resolvePostLoginMFAState resolves factor account and availability after successful auth.
func (h *FrontendHandler) resolvePostLoginMFAState(
	ctx *gin.Context,
	sp trace.Span,
	idpInstance *idp.NauthilusIDP,
	flowContext postLoginFlowContext,
	credentials postLoginCredentials,
	user *backend.User,
) (postLoginMFAState, bool) {
	factorUser, _, factorRef, err := h.resolveMFAFactorUser(ctx, idpInstance, credentials.username, user, flowContext.oidcCID, flowContext.samlEntityID)
	if err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()
		h.renderPostLoginFailure(ctx, flowContext.oidcCID, flowContext.samlEntityID, "Invalid login or password")

		return postLoginMFAState{}, false
	}

	return postLoginMFAState{
		user:         user,
		factorUser:   factorUser,
		factorRef:    factorRef,
		availability: h.getMFAAvailabilityWithBackendRef(ctx, factorUser, flowContext.protocol, flowContext.mgr, factorRef),
	}, true
}

// storeSuccessfulPostLoginSession persists the completed first-factor login.
func (h *FrontendHandler) storeSuccessfulPostLoginSession(
	ctx *gin.Context,
	flowContext postLoginFlowContext,
	credentials postLoginCredentials,
	user *backend.User,
) {
	if flowContext.mgr == nil {
		return
	}

	flowContext.mgr.Set(definitions.SessionKeyAccount, user.Name)
	flowContext.mgr.Set(definitions.SessionKeyUniqueUserID, user.ID)
	flowContext.mgr.Set(definitions.SessionKeyDisplayName, user.DisplayName)
	flowContext.mgr.Set(definitions.SessionKeySubject, user.ID)
	flowContext.mgr.Set(definitions.SessionKeyProtocol, flowContext.protocol)
	_ = setFlowAuthOutcome(ctx.Request.Context(), flowContext.mgr, h.deps.Redis, flowContext.redisPrefix, flowdomain.AuthOutcomeOK)

	if credentials.rememberMeTTL > 0 {
		flowContext.mgr.SetMaxAge(credentials.rememberMeTTL)
	}

	flowContext.mgr.Debug(ctx, h.deps.Logger, "Login successful - session data stored")
	advanceFlow(ctx.Request.Context(), flowContext.mgr, h.deps.Redis, flowContext.redisPrefix, flowdomain.FlowStepLogin)
}

// annotatePostLoginSpan records non-secret login identifiers on the active trace span.
func annotatePostLoginSpan(sp trace.Span, flowContext postLoginFlowContext, credentials postLoginCredentials) {
	sp.SetAttributes(
		attribute.String("username", credentials.username),
		attribute.String("oidc_cid", flowContext.oidcCID),
		attribute.String("saml_entity_id", flowContext.samlEntityID),
	)
}

// PostLogin handles the login submission.
// This endpoint is ONLY for IDP flows (OIDC/SAML2). Direct access without a proper flow is rejected.
// All flow state is read from the secure encrypted cookie - no form parameters for flow state.
func (h *FrontendHandler) PostLogin(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.isValidIDPFlow(ctx) {
		h.renderNoFlowError(ctx)

		return
	}

	flowContext := h.readPostLoginFlowContext(ctx)
	if flowContext.isDeviceCodeLoginFlow() {
		ctx.Redirect(http.StatusFound, h.deviceVerifyPath(ctx))

		return
	}

	credentials := h.readPostLoginCredentials(ctx, flowContext)
	h.logPostLoginAttempt(ctx, flowContext, credentials)

	idpInstance := idp.NewNauthilusIDP(h.deps)
	_ = resetFlowAuthOutcomeForLoginAttempt(ctx.Request.Context(), flowContext.mgr, h.deps.Redis, flowContext.redisPrefix)
	clearIDPAuthStatusBridge(flowContext.mgr)

	annotatePostLoginSpan(sp, flowContext, credentials)

	user, err := idpInstance.Authenticate(ctx, credentials.username, credentials.password, flowContext.oidcCID, flowContext.samlEntityID)
	if err != nil {
		h.handlePostLoginAuthFailure(ctx, sp, idpInstance, flowContext, credentials, err)
		return
	}

	mfaState, ok := h.resolvePostLoginMFAState(ctx, sp, idpInstance, flowContext, credentials, user)
	if !ok {
		return
	}

	if mfaState.availability.count > 0 {
		h.redirectPostLoginMFA(
			ctx,
			flowContext,
			credentials,
			mfaState,
			definitions.AuthResultOK,
			flowdomain.AuthOutcomeOK,
			"MFA required - pre-auth session data stored",
			true,
		)

		return
	}

	h.storeSuccessfulPostLoginSession(ctx, flowContext, credentials, user)
	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	if !h.checkRequireMFARegistrationAndRedirect(ctx, flowContext.mgr) {
		h.resumeIDPFlow(ctx, flowContext.mgr)
	}
}

// PostLoginWebAuthnFinish completes WebAuthn MFA and returns the server-derived
// continuation target for the surrounding IDP flow.
func (h *FrontendHandler) PostLoginWebAuthnFinish(ctx *gin.Context) {
	if _, ok := core.CompleteLoginWebAuthn(ctx, h.deps.Auth()); !ok {
		return
	}

	mgr := cookie.GetManager(ctx)

	redirectURI, ok := h.loginWebAuthnCompletionRedirect(ctx, mgr)
	if !ok {
		return
	}

	if redirectURI == flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
		h.completeDeviceCodeFlow(ctx, mgr)

		return
	}

	ctx.JSON(http.StatusOK, webAuthnFinishResponse{Redirect: redirectURI})
}

// loginWebAuthnCompletionRedirect mirrors the post-MFA continuation used by
// TOTP, but returns a transport-neutral target for the JavaScript WebAuthn flow.
func (h *FrontendHandler) loginWebAuthnCompletionRedirect(ctx *gin.Context, mgr cookie.Manager) (string, bool) {
	if redirectURI, ok := h.pendingSelfServiceStepUpRedirectURI(ctx, mgr); ok {
		return redirectURI, true
	}

	if redirectURI, ok := h.requireMFARegistrationRedirectURI(ctx, mgr); ok {
		return redirectURI, true
	}

	return h.resumeIDPFlowRedirectURI(ctx, mgr)
}

func (h *FrontendHandler) hasTOTP(user *backend.User) bool {
	if user == nil {
		return false
	}

	totpField := user.TOTPSecretField

	if totpField == "" && h != nil && h.deps != nil && h.deps.Cfg != nil {
		if protocols := safeLDAPSearchConfig(h.deps.Cfg); len(protocols) > 0 {
			totpField = protocols[0].GetTotpSecretField()
		}
	}

	if totpField != "" {
		if val, ok := user.Attributes[totpField]; ok {
			if len(val) > 0 && val[0] != "" {
				return true
			}
		}
	}

	return false
}

// safeLDAPSearchConfig returns configured LDAP search protocols when an LDAP
// section is available.
func safeLDAPSearchConfig(cfg config.File) []config.LDAPSearchProtocol {
	if cfg == nil {
		return nil
	}

	ldapConfig := cfg.GetLDAP()
	if ldapConfig == nil {
		return nil
	}

	return ldapConfig.GetSearch()
}

// hasWebAuthn reports whether the user has any registered WebAuthn credential.
func (h *FrontendHandler) hasWebAuthn(ctx *gin.Context, user *backend.User, protocolName string) bool {
	if mgr := cookie.GetManager(ctx); mgr != nil && mgr.GetBool(definitions.SessionKeyHaveWebAuthn, false) {
		return true
	}

	return h.hasWebAuthnWithBackendRef(ctx, user, protocolName, core.RemoteBackendRef{})
}

// hasWebAuthnWithBackendRef binds credential lookups to an explicit authority backend reference when present.
func (h *FrontendHandler) hasWebAuthnWithBackendRef(ctx *gin.Context, user *backend.User, protocolName string, backendRef core.RemoteBackendRef) bool {
	return h.hasWebAuthnWithProviderAndBackendRef(ctx, user, protocolName, nil, backendRef)
}

// hasWebAuthnWithProvider checks credentials through the supplied provider or a session-derived AuthState.
func (h *FrontendHandler) hasWebAuthnWithProvider(ctx *gin.Context, user *backend.User, protocolName string, provider webAuthnCredentialProvider) bool {
	return h.hasWebAuthnWithProviderAndBackendRef(ctx, user, protocolName, provider, core.RemoteBackendRef{})
}

// hasWebAuthnWithProviderAndBackendRef resolves WebAuthn credentials while preserving the selected backend authority.
func (h *FrontendHandler) hasWebAuthnWithProviderAndBackendRef(ctx *gin.Context, user *backend.User, protocolName string, provider webAuthnCredentialProvider, backendRef core.RemoteBackendRef) bool {
	if ctx == nil || user == nil {
		return false
	}

	lookupCtx := backendDataLookupContext(ctx)
	mgr := cookie.GetManager(ctx)

	if provider == nil {
		authDeps := h.deps.Auth()

		state := core.NewAuthStateWithSetupWithDeps(lookupCtx, authDeps)
		if state == nil {
			return false
		}

		resolvedProtocol := protocolName
		if resolvedProtocol == "" && mgr != nil {
			resolvedProtocol = mgr.GetString(definitions.SessionKeyProtocol, "")
		}

		if resolvedProtocol == "" {
			resolvedProtocol = definitions.ProtoIDP
		}

		authState := state.(*core.AuthState)
		authState.SetUsername(user.Name)
		authState.SetProtocol(config.NewProtocol(resolvedProtocol))
		authState.SetNoAuth(true)

		if !backendRef.IsZero() {
			authState.Runtime.RemoteBackendRef = backendRef
		} else if ref, ok := core.RemoteBackendRefForAuthSession(authState, mgr); ok {
			authState.Runtime.RemoteBackendRef = ref
		}

		provider = authState
	}

	data := &UserBackendData{
		Username:     user.Name,
		DisplayName:  user.DisplayName,
		UniqueUserID: user.ID,
	}

	h.resolveWebAuthnUser(lookupCtx, nil, data, provider)

	return data.HaveWebAuthn
}

func (h *FrontendHandler) hasRecoveryCodes(user *backend.User) bool {
	if user == nil {
		return false
	}

	recoveryField := user.TOTPRecoveryField

	if recoveryField == "" {
		if h == nil || h.deps == nil || h.deps.Cfg == nil {
			return false
		}

		if protocols := safeLDAPSearchConfig(h.deps.Cfg); len(protocols) > 0 {
			recoveryField = protocols[0].GetTotpRecoveryField()
		}
	}

	if recoveryField != "" {
		if val, ok := user.Attributes[recoveryField]; ok {
			return len(val) > 0
		}
	}

	return false
}

// LoginMFASelect renders the MFA selection page.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginMFASelect(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	h.prepareExistingSessionMFAAssuranceChallenge(mgr)

	username, protocol := readLoginMFASelectSession(mgr)
	if username == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	user, ok := h.loginMFASelectUser(ctx, mgr, username)
	if !ok {
		return
	}

	availability := h.getMFAAvailability(ctx, user, protocol, mgr)
	if mgr != nil {
		mgr.Set(definitions.SessionKeyMFAMulti, availability.count > 1)
	}

	if redirectURL, ok := h.getMFARedirectURLFromCookie(ctx, user); ok {
		ctx.Redirect(http.StatusFound, redirectURL)
		return
	}

	ctx.HTML(http.StatusOK, "idp_mfa_select.html", h.loginMFASelectPageData(ctx, availability))
}

// readLoginMFASelectSession returns the username and protocol for MFA selection.
func readLoginMFASelectSession(mgr cookie.Manager) (string, string) {
	if mgr == nil {
		return "", ""
	}

	username := mgr.GetString(definitions.SessionKeyUsername, "")
	if factorUser := mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""); factorUser != "" {
		username = factorUser
	}

	if username == "" {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	return username, mgr.GetString(definitions.SessionKeyIDPFlowType, "")
}

// loginMFASelectUser loads the user for MFA availability checks.
func (h *FrontendHandler) loginMFASelectUser(ctx *gin.Context, mgr cookie.Manager, username string) (*backend.User, bool) {
	idpInstance := idp.NewNauthilusIDP(h.deps)
	oidcCID, samlEntityID := h.getFlowClientIdentifiers(mgr)

	user, err := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID)
	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return nil, false
	}

	return user, true
}

// recommendedMFAMethod returns the last usable MFA method.
func recommendedMFAMethod(ctx *gin.Context, availability mfaAvailability) (string, string) {
	lastMFA, _ := ctx.Cookie("last_mfa_method")

	switch lastMFA {
	case mfaMethodTOTP:
		if availability.haveTOTP {
			return lastMFA, mfaMethodTOTP
		}
	case mfaMethodWebAuthn:
		if availability.haveWebAuthn {
			return lastMFA, mfaMethodWebAuthn
		}
	case mfaMethodRecovery:
		if availability.haveRecoveryCodes {
			return lastMFA, mfaMethodRecovery
		}
	}

	return lastMFA, ""
}

// hasOtherMFAMethods reports whether alternatives to the recommended method exist.
func hasOtherMFAMethods(availability mfaAvailability, recommendedMethod string) bool {
	return recommendedMethod != "" && ((availability.haveTOTP && recommendedMethod != mfaMethodTOTP) ||
		(availability.haveWebAuthn && recommendedMethod != mfaMethodWebAuthn) ||
		(availability.haveRecoveryCodes && recommendedMethod != mfaMethodRecovery))
}

// loginMFASelectPageData builds template data for MFA selection.
func (h *FrontendHandler) loginMFASelectPageData(ctx *gin.Context, availability mfaAvailability) gin.H {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["SelectMFA"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Select Multi-Factor Authentication")
	data["ChooseMFADescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Choose your preferred second factor")
	data["AuthenticatorApp"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Authenticator App")
	data["SecurityKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Key")
	data["RecoveryCode"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
	data["Recommended"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recommended")
	data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	data["HaveTOTP"] = availability.haveTOTP
	data["HaveWebAuthn"] = availability.haveWebAuthn
	data["HaveRecoveryCodes"] = availability.haveRecoveryCodes
	data["TOTPLoginEndpoint"] = localizedLoginPath(ctx, "/login/totp")
	data["WebAuthnLoginEndpoint"] = localizedLoginPath(ctx, "/login/webauthn")
	data["RecoveryLoginEndpoint"] = localizedLoginPath(ctx, "/login/recovery")

	lastMFA, recommendedMethod := recommendedMFAMethod(ctx, availability)

	data["LastMFAMethod"] = lastMFA
	data["RecommendedMethod"] = recommendedMethod
	data["HasOtherMethods"] = hasOtherMFAMethods(availability, recommendedMethod)
	data["OtherMethods"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Other methods")
	data["BackURL"] = h.getLoginPath(ctx)

	return data
}

// loginMFAVerificationPage describes the localized data required for a login MFA verification page.
type loginMFAVerificationPage struct {
	method          string
	templateName    string
	messageDataKey  string
	messageText     string
	codeText        string
	postEndpointKey string
}

// renderLoginMFAVerificationPage renders a cookie-bound login MFA challenge page.
func (h *FrontendHandler) renderLoginMFAVerificationPage(ctx *gin.Context, page loginMFAVerificationPage) {
	mgr := cookie.GetManager(ctx)
	h.prepareExistingSessionMFAAssuranceChallenge(mgr)

	if username, _ := readLoginMFASelectSession(mgr); username == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	if !h.isMFAMethodSupported(mgr, page.method) {
		ctx.Redirect(http.StatusFound, h.getMFASelectPath(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data[page.messageDataKey] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, page.messageText)
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, page.codeText)
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = csrf.Token(ctx)
	data[page.postEndpointKey] = ctx.Request.URL.Path
	data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)
	data["HaveError"] = false

	ctx.HTML(http.StatusOK, page.templateName, data)
}

// LoginRecovery renders the recovery code verification page during login.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginRecovery(ctx *gin.Context) {
	h.renderLoginMFAVerificationPage(ctx, loginMFAVerificationPage{
		method:          definitions.MFAMethodRecoveryCodes,
		templateName:    "idp_recovery_login.html",
		messageDataKey:  "RecoveryVerifyMessage",
		messageText:     "Please enter one of your recovery codes",
		codeText:        "Recovery Code",
		postEndpointKey: "PostRecoveryVerifyEndpoint",
	})
}

// mfaSessionState holds the common session state extracted for MFA verification handlers.
type mfaSessionState struct {
	mgr          cookie.Manager
	username     string
	factorUser   string
	oidcCID      string
	samlEntityID string
}

// extractMFASessionAndUser reads the MFA session state and form code from the cookie/request,
// validates presence of required fields, and looks up the user. Returns nil if any step fails
// (the caller is redirected to the login page in that case).
func (h *FrontendHandler) extractMFASessionAndUser(ctx *gin.Context) (*mfaSessionState, *backend.User, string) {
	mgr := cookie.GetManager(ctx)

	var (
		username      string
		factorUser    string
		hasAuthResult bool
		oidcCID       string
		samlEntityID  string
	)

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyUsername, "")
		factorUser = mgr.GetString(definitions.SessionKeyMFAFactorAccount, "")
		hasAuthResult = mgr.HasKey(definitions.SessionKeyAuthResult)

		flowType := mgr.GetString(definitions.SessionKeyIDPFlowType, "")

		switch flowType {
		case definitions.ProtoOIDC:
			oidcCID = mgr.GetString(definitions.SessionKeyIDPClientID, "")
		case definitions.ProtoSAML:
			samlEntityID = mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, "")
			if samlEntityID == "" {
				samlEntityID = definitions.ProtoSAML
			}
		}
	}

	code := ctx.PostForm("code")

	if username == "" || !hasAuthResult || code == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return nil, nil, ""
	}

	if factorUser == "" {
		factorUser = username
	}

	state := &mfaSessionState{
		mgr:          mgr,
		username:     username,
		factorUser:   factorUser,
		oidcCID:      oidcCID,
		samlEntityID: samlEntityID,
	}

	user := &backend.User{
		Name:        mgr.GetString(definitions.SessionKeyMFAAccount, username),
		ID:          mgr.GetString(definitions.SessionKeyUniqueUserID, ""),
		DisplayName: mgr.GetString(definitions.SessionKeyMFADisplayName, ""),
	}

	return state, user, code
}

// loadCompletedMFAUser refreshes the target account after factor verification succeeded.
func (h *FrontendHandler) loadCompletedMFAUser(ctx *gin.Context, sess *mfaSessionState, fallback *backend.User) (*backend.User, error) {
	if sess == nil || sess.mgr == nil {
		return fallback, nil
	}

	username := sess.mgr.GetString(definitions.SessionKeyMFAAccount, sess.username)
	if username == "" {
		return fallback, nil
	}

	idpInstance := idp.NewNauthilusIDP(h.deps)

	user, err := idpInstance.GetUserByUsername(ctx, username, sess.oidcCID, sess.samlEntityID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// PostLoginRecovery handles the recovery code verification during login.
// All flow state is read from the encrypted cookie - no form parameters for flow state.
func (h *FrontendHandler) PostLoginRecovery(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login_recovery")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	sess, user, code := h.extractMFASessionAndUser(ctx)
	if sess == nil {
		return
	}

	if !h.isMFAMethodSupported(sess.mgr, definitions.MFAMethodRecoveryCodes) {
		ctx.Redirect(http.StatusFound, h.getMFASelectPath(ctx))

		return
	}

	success, err := h.mfa.UseRecoveryCode(ctx, sess.factorUser, code, userBackendFromMFASession(sess.mgr))
	if err != nil {
		h.deps.Logger.Error("Failed to use recovery code", "error", err)
	}

	if !success {
		h.renderRecoveryCodeFailure(ctx, sess, err)

		return
	}

	core.LogIDPMFAuthResult(ctx, h.deps.Auth(), sess.factorUser, definitions.MFAMethodRecoveryCodes, "", true)

	// MFA OK. Now check if the original password was OK (delayed response case).
	if h.handleDelayedResponseFailure(ctx, sess, "recovery") {
		return
	}

	// All OK!
	h.setLastMFAMethod(ctx, "recovery")

	user, err = h.loadCompletedMFAUser(ctx, sess, user)
	if err != nil {
		sp.RecordError(err)
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	h.finalizeMFALogin(ctx, user)
}

// renderRecoveryCodeFailure renders the recovery-code form after a failed code attempt.
func (h *FrontendHandler) renderRecoveryCodeFailure(ctx *gin.Context, sess *mfaSessionState, err error) {
	core.LogIDPMFAuthResult(
		ctx,
		h.deps.Auth(),
		sess.factorUser,
		definitions.MFAMethodRecoveryCodes,
		mfaFailureStatus("Invalid recovery code", err),
		false,
	)

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["RecoveryVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter one of your recovery codes")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")
	data["CSRFToken"] = csrf.Token(ctx)
	data["PostRecoveryVerifyEndpoint"] = ctx.Request.URL.Path
	data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)
	data["HaveError"] = true
	data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid recovery code")

	ctx.HTML(http.StatusOK, "idp_recovery_login.html", data)
}

// userBackendFromMFASession returns the backend type recorded for MFA verification.
func userBackendFromMFASession(mgr cookie.Manager) uint8 {
	if mgr == nil {
		return uint8(definitions.BackendLDAP)
	}

	return mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
}

// mfaFailureStatus returns the log status for an MFA failure.
func mfaFailureStatus(defaultStatus string, err error) string {
	if err != nil {
		return err.Error()
	}

	return defaultStatus
}

func (h *FrontendHandler) setLastMFAMethod(ctx *gin.Context, method string) {
	secure := util.ShouldSetSecureCookie()

	ctx.SetCookie("last_mfa_method", method, 365*24*60*60, "/", "", secure, true)

	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Set(definitions.SessionKeyMFAMethod, method)
	}
}

func (h *FrontendHandler) getMFAAvailability(ctx *gin.Context, user *backend.User, protocolParam string, mgr cookie.Manager) mfaAvailability {
	return h.getMFAAvailabilityWithBackendRef(ctx, user, protocolParam, mgr, core.RemoteBackendRef{})
}

// getMFAAvailabilityWithBackendRef evaluates active MFA methods against the selected backend identity.
func (h *FrontendHandler) getMFAAvailabilityWithBackendRef(ctx *gin.Context, user *backend.User, protocolParam string, mgr cookie.Manager, backendRef core.RemoteBackendRef) mfaAvailability {
	availability := mfaAvailability{
		haveTOTP:          h.hasTOTP(user),
		haveWebAuthn:      h.hasWebAuthnWithBackendRef(ctx, user, protocolParam, backendRef),
		haveRecoveryCodes: h.hasRecoveryCodes(user),
	}

	h.mergeBackendMFAAvailability(ctx, mgr, user, protocolParam, backendRef, &availability)
	applySessionMFAAvailabilitySnapshot(mgr, &availability)
	h.applySupportedMFAFilter(mgr, &availability)
	availability.count = countMFAAvailability(availability)
	storeMFAAvailabilitySnapshot(mgr, availability)

	return availability
}

// applySessionMFAAvailabilitySnapshot preserves factor facts already proven in
// this encrypted browser session before applying the client supported_mfa allow-list.
func applySessionMFAAvailabilitySnapshot(mgr cookie.Manager, availability *mfaAvailability) {
	if mgr == nil || availability == nil {
		return
	}

	availability.haveTOTP = availability.haveTOTP || mgr.GetBool(definitions.SessionKeyHaveTOTP, false)
	availability.haveWebAuthn = availability.haveWebAuthn || mgr.GetBool(definitions.SessionKeyHaveWebAuthn, false)
	availability.haveRecoveryCodes = availability.haveRecoveryCodes || mgr.GetBool(definitions.SessionKeyHaveRecoveryCodes, false)
}

// mergeBackendMFAAvailability adds public backend MFA state to attribute-based checks.
func (h *FrontendHandler) mergeBackendMFAAvailability(
	ctx *gin.Context,
	mgr cookie.Manager,
	user *backend.User,
	protocolParam string,
	backendRef core.RemoteBackendRef,
	availability *mfaAvailability,
) {
	if h == nil || h.deps == nil || ctx == nil || user == nil || availability == nil {
		return
	}

	data, err := h.getUserBackendDataForIdentity(ctx, mgr, user.Name, protocolParam, backendRef)
	if err != nil || data == nil {
		return
	}

	availability.haveTOTP = availability.haveTOTP || data.HaveTOTP
	availability.haveWebAuthn = availability.haveWebAuthn || data.HaveWebAuthn
	availability.haveRecoveryCodes = availability.haveRecoveryCodes || data.NumRecoveryCodes > 0
}

// applySupportedMFAFilter removes methods disallowed by the active client policy.
func (h *FrontendHandler) applySupportedMFAFilter(mgr cookie.Manager, availability *mfaAvailability) {
	if h == nil || availability == nil {
		return
	}

	if !h.isMFAMethodSupported(mgr, definitions.MFAMethodTOTP) {
		availability.haveTOTP = false
	}

	if !h.isMFAMethodSupported(mgr, definitions.MFAMethodWebAuthn) {
		availability.haveWebAuthn = false
	}

	if !h.isMFAMethodSupported(mgr, definitions.MFAMethodRecoveryCodes) {
		availability.haveRecoveryCodes = false
	}
}

// countMFAAvailability counts recovery codes only when another MFA method exists.
func countMFAAvailability(availability mfaAvailability) int {
	count := 0

	if availability.haveTOTP {
		count++
	}

	if availability.haveWebAuthn {
		count++
	}

	if count != 0 && availability.haveRecoveryCodes {
		count++
	}

	return count
}

// storeMFAAvailabilitySnapshot preserves enrolled-factor facts across MFA cleanup.
func storeMFAAvailabilitySnapshot(mgr cookie.Manager, availability mfaAvailability) {
	if mgr == nil {
		return
	}

	mgr.Set(definitions.SessionKeyHaveTOTP, availability.haveTOTP)
	mgr.Set(definitions.SessionKeyHaveWebAuthn, availability.haveWebAuthn)
	mgr.Set(definitions.SessionKeyHaveRecoveryCodes, availability.haveRecoveryCodes)
}

// getMFARedirectURLFromCookie returns the MFA redirect URL based on user's available MFA methods.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) getMFARedirectURLFromCookie(ctx *gin.Context, user *backend.User) (string, bool) {
	mgr := cookie.GetManager(ctx)
	protocolParam := ""

	if mgr != nil {
		protocolParam = mgr.GetString(definitions.SessionKeyIDPFlowType, "")
	}

	availability := h.getMFAAvailability(ctx, user, protocolParam, mgr)

	path, ok := h.getMFARedirectURLFromAvailability(availability)
	if !ok {
		return "", false
	}

	return localizedLoginPath(ctx, path), true
}

// getMFARedirectURLFromAvailability returns the direct challenge URL when exactly one method is available.
func (h *FrontendHandler) getMFARedirectURLFromAvailability(availability mfaAvailability) (string, bool) {
	if availability.count > 1 {
		return "", false
	}

	var target string

	if availability.haveTOTP {
		target = "/login/totp"
	} else if availability.haveWebAuthn {
		target = "/login/webauthn"
	} else if availability.haveRecoveryCodes {
		target = "/login/recovery"
	} else {
		// No MFA methods available
		return "", false
	}

	// No query parameters needed - all flow state is in the cookie
	return target, true
}

// getMFAURLFromCookie returns the URL for a specific MFA method.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) getMFAURLFromCookie(ctx *gin.Context, mfaType string) string {
	return localizedLoginPath(ctx, "/login/"+mfaType)
}

// getLoginMFABackURLFromCookie returns the URL to go back from MFA verification.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) getLoginMFABackURLFromCookie(ctx *gin.Context) string {
	mgr := cookie.GetManager(ctx)
	multi := false

	if mgr != nil {
		multi = mgr.GetBool(definitions.SessionKeyMFAMulti, false)
	}

	if !multi {
		return h.getLoginPath(ctx)
	}

	return h.getMFASelectPath(ctx)
}

// finalizeMFALogin completes the MFA login process and redirects to the IDP endpoint.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) finalizeMFALogin(ctx *gin.Context, user *backend.User) {
	mgr := cookie.GetManager(ctx)

	if mgr != nil {
		core.StoreCompletedIDPMFASession(mgr, user, mgr.GetString(definitions.SessionKeyMFAMethod, ""))
		mgr.Debug(ctx, h.deps.Logger, "MFA login finalized - session data stored")
	}

	core.QueueCompletedIDPMFAPostAction(ctx, h.deps.Auth(), user)

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	// Redirect back to IDP endpoint; check for mandatory MFA registration first.
	if h.redirectPendingSelfServiceStepUp(ctx, mgr) {
		return
	}

	if !h.checkRequireMFARegistrationAndRedirect(ctx, mgr) {
		h.resumeIDPFlow(ctx, mgr)
	}
}

// LoginWebAuthn renders the WebAuthn verification page during login.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginWebAuthn(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	h.prepareExistingSessionMFAAssuranceChallenge(mgr)

	username := ""

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyUsername, "")
	}

	if username == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	if !h.isMFAMethodSupported(mgr, definitions.MFAMethodWebAuthn) {
		ctx.Redirect(http.StatusFound, h.getMFASelectPath(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["WebAuthnVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please use your security key to login")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = csrf.Token(ctx)
	data["WebAuthnBeginEndpoint"] = h.getMFAURLFromCookie(ctx, "webauthn/begin")
	data["WebAuthnFinishEndpoint"] = h.getMFAURLFromCookie(ctx, "webauthn/finish")
	data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)

	// JS Localizations
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing login...")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")

	ctx.HTML(http.StatusOK, "idp_webauthn_verify.html", data)
}

// LoginTOTP renders the TOTP verification page during login.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginTOTP(ctx *gin.Context) {
	h.renderLoginMFAVerificationPage(ctx, loginMFAVerificationPage{
		method:          definitions.MFAMethodTOTP,
		templateName:    "idp_totp_verify.html",
		messageDataKey:  "TOTPVerifyMessage",
		messageText:     "Please enter your 2FA code",
		codeText:        "OTP Code",
		postEndpointKey: "PostTOTPVerifyEndpoint",
	})
}

// PostLoginTOTP handles the TOTP verification during login.
// All flow state is read from the encrypted cookie - no form parameters for flow state.
func (h *FrontendHandler) PostLoginTOTP(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login_totp")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	sess, user, code := h.extractMFASessionAndUser(ctx)
	if sess == nil {
		return
	}

	if !h.isMFAMethodSupported(sess.mgr, definitions.MFAMethodTOTP) {
		ctx.Redirect(http.StatusFound, h.getMFASelectPath(ctx))

		return
	}

	valid, err := h.mfa.VerifyTOTP(ctx, sess.factorUser, code, userBackendFromMFASession(sess.mgr))
	if err != nil || !valid {
		if err != nil {
			sp.RecordError(err)
		}

		h.renderTOTPLoginFailure(ctx, sess, err)

		return
	}

	core.LogIDPMFAuthResult(ctx, h.deps.Auth(), sess.factorUser, definitions.MFAMethodTOTP, "", true)

	// MFA OK. Now check if the original password was OK (delayed response case).
	if h.handleDelayedResponseFailure(ctx, sess, "totp") {
		return
	}

	// All OK!
	h.setLastMFAMethod(ctx, "totp")

	user, err = h.loadCompletedMFAUser(ctx, sess, user)
	if err != nil {
		sp.RecordError(err)
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	h.finalizeMFALogin(ctx, user)
}

// renderTOTPLoginFailure renders the TOTP form after a failed OTP attempt.
func (h *FrontendHandler) renderTOTPLoginFailure(ctx *gin.Context, sess *mfaSessionState, err error) {
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "totp", "fail").Inc()
	core.LogIDPMFAuthResult(
		ctx,
		h.deps.Auth(),
		sess.factorUser,
		definitions.MFAMethodTOTP,
		mfaFailureStatus("Invalid OTP code", err),
		false,
	)

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["CSRFToken"] = csrf.Token(ctx)
	data["PostTOTPVerifyEndpoint"] = ctx.Request.URL.Path
	data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)
	data["HaveError"] = true
	data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid OTP code")

	ctx.HTML(http.StatusOK, "idp_totp_verify.html", data)
}

// TwoFAHome renders the 2FA management overview.
func (h *FrontendHandler) TwoFAHome(ctx *gin.Context) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IDP 2FA Self-Service home request",
	)

	mgr := cookie.GetManager(ctx)
	data := h.basePageData(ctx)

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Self-Service")
	data["AuthenticatorAppTOTP"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Authenticator App (TOTP)")
	data["TOTPDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Use an app like Google Authenticator or Authy.")
	data["SecurityKeyWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Key (WebAuthn)")
	data["WebAuthnDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Use a physical key like Yubikey.")
	data["RegisterTOTP"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP")
	data["RegisterWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn")
	data["Deactivate"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deactivate")
	data["DeactivateTOTPConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to deactivate TOTP?")
	data["DeactivateWebAuthnConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to deactivate WebAuthn?")
	data["RecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Codes")
	data["RecoveryCodesDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup codes can be used to log in if you lose access to your 2FA device.")
	data["RecoveryCodesLeft"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You have %d recovery codes left.")
	data["GenerateNewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Generate new recovery codes")
	data["GenerateRecoveryCodesConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to generate new recovery codes? Any existing codes will be permanently replaced.")
	data["TOTPDeleteEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/totp")
	data["TOTPRegisterEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/totp/register")
	data["WebAuthnDevicesEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/devices")
	data["WebAuthnRegisterEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/register")
	data["RecoveryGenerateEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/recovery/generate")
	data["Home"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Home")

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.handleTwoFAHomeError(ctx, data, err, "")

		return
	}

	data["Username"] = userData.Username
	data["DisplayName"] = userData.DisplayName
	data["HaveTOTP"] = userData.HaveTOTP
	data["HaveRecoveryCodes"] = userData.NumRecoveryCodes > 0
	data["NumRecoveryCodes"] = userData.NumRecoveryCodes
	data["HaveWebAuthn"] = userData.HaveWebAuthn

	// Sync cookie if account exists
	if mgr != nil && mgr.GetString(definitions.SessionKeyAccount, "") != "" {
		mgr.Set(definitions.SessionKeyHaveTOTP, userData.HaveTOTP)
	}

	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_2fa_home.html", data)
}

func (h *FrontendHandler) handleTwoFAHomeError(ctx *gin.Context, data gin.H, err error, username string) {
	h.deps.Logger.Error("Session error in TwoFAHome",
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		"username", username,
		definitions.LogKeyError, err,
	)

	data["BackendError"] = true
	data["BackendErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An internal error occurred. Please contact your administrator.")
	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_2fa_home.html", data)
}

// RegisterTOTP renders the TOTP registration page.
func (h *FrontendHandler) RegisterTOTP(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	haveTOTP := false
	account := ""
	sourceBackend := uint8(definitions.BackendLDAP)

	if mgr != nil {
		haveTOTP = mgr.GetBool(definitions.SessionKeyHaveTOTP, false)
		account = mgr.GetString(definitions.SessionKeyAccount, "")
		sourceBackend = mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	if haveTOTP {
		// In a forced-registration flow redirect to the continue endpoint so the
		// next required method (if any) is handled; otherwise go to the self-service home.
		if mgr != nil && mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
			ctx.Redirect(http.StatusFound, definitions.MFARoot+"/register/continue")
		} else {
			ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
			ctx.Status(http.StatusFound)
		}

		return
	}

	if account == "" {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	secret, qrCodeURL, err := h.mfa.GenerateTOTPSecret(ctx, account)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to generate TOTP key")

		return
	}

	if mgr != nil && sourceBackend != uint8(definitions.BackendRemote) {
		mgr.Set(definitions.SessionKeyTOTPSecret, secret)
	} else if mgr != nil {
		mgr.Delete(definitions.SessionKeyTOTPSecret)
	}

	data := h.basePageData(ctx)
	data["QRCode"] = qrCodeURL
	data["Secret"] = secret
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP")
	data["TOTPMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please scan and verify the following QR code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["CSRFToken"] = csrf.Token(ctx)
	data["PostTOTPRegisterPath"] = localizedMFARootPath(ctx, definitions.MFARoot+"/totp/register")

	requireFlow := mgr != nil && mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false)

	data["RequireMFAFlow"] = requireFlow
	data["RequireMFAMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Your application requires this authentication method to be set up before you can continue")
	data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
	data["CancelMFAEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/register/cancel")

	ctx.HTML(http.StatusOK, "idp_totp_register.html", data)
}

// PostRegisterTOTP handles the TOTP registration submission.
func (h *FrontendHandler) PostRegisterTOTP(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_register_totp")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	mgr := cookie.GetManager(ctx)
	secret := ""
	username := ""
	sourceBackend := uint8(definitions.BackendLDAP)

	if mgr != nil {
		secret = mgr.GetString(definitions.SessionKeyTOTPSecret, "")
		username = mgr.GetString(definitions.SessionKeyAccount, "")
		sourceBackend = mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	code := ctx.PostForm("code")

	if username == "" || code == "" || (sourceBackend != uint8(definitions.BackendRemote) && secret == "") {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	if err := h.mfa.VerifyAndSaveTOTP(ctx, username, secret, code, sourceBackend); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to register TOTP", err)

		return
	}

	auth := core.NewAuthStateFromContextWithDeps(ctx, h.deps.Auth())
	auth.PurgeCacheFor(username)

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "success").Inc()

	if mgr != nil {
		mgr.Set(definitions.SessionKeyHaveTOTP, true)
		mgr.Delete(definitions.SessionKeyTOTPSecret)
	}

	// In a forced-registration flow the pending list must be updated and the browser
	// must be sent to the continue endpoint so that the next required method (if any)
	// is registered before the IDP flow resumes.
	if mgr != nil && mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		h.removeCompletedRequireMFAMethod(ctx, mgr, definitions.MFAMethodTOTP)

		ctx.Header("HX-Redirect", definitions.MFARoot+"/register/continue")
		ctx.Status(http.StatusOK)

		return
	}

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// recoveryRegistrationContext carries session state for recovery-code registration.
type recoveryRegistrationContext struct {
	mgr           cookie.Manager
	account       string
	sourceBackend uint8
	requireFlow   bool
}

// newRecoveryRegistrationContext reads recovery-code registration state.
func newRecoveryRegistrationContext(ctx *gin.Context) recoveryRegistrationContext {
	context := recoveryRegistrationContext{
		mgr:           cookie.GetManager(ctx),
		sourceBackend: uint8(definitions.BackendLDAP),
	}
	if context.mgr == nil {
		return context
	}

	context.account = context.mgr.GetString(definitions.SessionKeyAccount, "")
	context.sourceBackend = context.mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	context.requireFlow = context.mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false)
	context.mgr.Delete(definitions.SessionKeyRecoveryCodesSaved)
	context.mgr.Delete(definitions.SessionKeyRecoveryCodesRemoteGenerated)

	return context
}

// missingRecoveryRegistrationMethods returns required MFA methods still missing.
func missingRecoveryRegistrationMethods(required []string, userData *UserBackendData) []string {
	missing := make([]string, 0, len(required))

	for _, method := range required {
		if recoveryRegistrationMethodMissing(method, userData) {
			missing = append(missing, method)
		}
	}

	return missing
}

// recoveryRegistrationMethodMissing checks one required MFA method.
func recoveryRegistrationMethodMissing(method string, userData *UserBackendData) bool {
	switch method {
	case definitions.MFAMethodTOTP:
		return !userData.HaveTOTP
	case definitions.MFAMethodWebAuthn:
		return !userData.HaveWebAuthn
	case definitions.MFAMethodRecoveryCodes:
		return userData.NumRecoveryCodes == 0
	default:
		return false
	}
}

// updateRecoveryRequireFlow refreshes required-MFA state from backend data.
func (h *FrontendHandler) updateRecoveryRequireFlow(context *recoveryRegistrationContext, userData *UserBackendData) {
	if context.mgr == nil || context.requireFlow || context.mgr.GetString(definitions.SessionKeyIDPFlowID, "") == "" {
		return
	}

	required := h.getRequiredMFAMethods(context.mgr)
	if len(required) == 0 {
		return
	}

	missing := missingRecoveryRegistrationMethods(required, userData)
	if len(missing) == 0 {
		return
	}

	context.requireFlow = true
	flowdomain.SetRequireMFAPending(context.mgr, strings.Join(missing, ","))
}

// redirectExistingRecoveryCodes handles users who already have recovery codes.
func (h *FrontendHandler) redirectExistingRecoveryCodes(ctx *gin.Context, requireFlow bool) {
	if requireFlow {
		ctx.Redirect(http.StatusFound, definitions.MFARoot+"/register/continue")

		return
	}

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusFound)
}

// generateRecoveryRegistrationCodes creates codes for remote or local backends.
func (h *FrontendHandler) generateRecoveryRegistrationCodes(ctx *gin.Context, context recoveryRegistrationContext) ([]string, bool) {
	if context.sourceBackend == uint8(definitions.BackendRemote) {
		codes, err := h.mfa.GenerateRecoveryCodes(ctx, context.account, context.sourceBackend)
		if err != nil {
			h.renderErrorModalWithErr(ctx, "Failed to generate recovery codes", err)

			return nil, false
		}

		if context.mgr != nil {
			context.mgr.Set(definitions.SessionKeyRecoveryCodesRemoteGenerated, true)
		}

		return codes, true
	}

	recovery, err := core.GenerateBackupCodes()
	if err != nil {
		h.renderErrorModalWithErr(ctx, "Failed to generate recovery codes", err)

		return nil, false
	}

	codes := recovery.GetCodes()
	if context.mgr != nil {
		context.mgr.Set(definitions.SessionKeyRecoveryCodes, strings.Join(codes, ","))
	}

	return codes, true
}

// recoveryCodesRegisterPageData builds the registration page data.
func (h *FrontendHandler) recoveryCodesRegisterPageData(ctx *gin.Context, codes []string, requireFlow bool) gin.H {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Codes")
	data["BackupTheseCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup these codes!")
	data["ShownOnlyOnce"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "They will be shown only once.")
	data["Copy"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Copy")
	data["Download"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Download")
	data["Downloaded"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Downloaded")
	data["Continue"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Continue")
	data["CopiedToClipboard"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Copied to clipboard")
	data["Codes"] = codes
	data["CSRFToken"] = csrf.Token(ctx)
	data["SaveRecoveryCodesEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/recovery/register/save")
	data["PostRecoveryRegisterEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/recovery/register")
	data["RequireMFAFlow"] = requireFlow
	data["RequireMFAMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Your application requires this authentication method to be set up before you can continue")
	data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
	data["CancelMFAEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/register/cancel")

	return data
}

// RegisterRecoveryCodes renders the recovery codes registration page.
func (h *FrontendHandler) RegisterRecoveryCodes(ctx *gin.Context) {
	context := newRecoveryRegistrationContext(ctx)
	if context.account == "" {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Failed to fetch user data")

		return
	}

	h.updateRecoveryRequireFlow(&context, userData)

	if userData.NumRecoveryCodes > 0 {
		h.redirectExistingRecoveryCodes(ctx, context.requireFlow)
		return
	}

	codes, ok := h.generateRecoveryRegistrationCodes(ctx, context)
	if !ok {
		return
	}

	ctx.HTML(http.StatusOK, "idp_recovery_codes_register.html", h.recoveryCodesRegisterPageData(ctx, codes, context.requireFlow))
}

// saveRecoveryCodesContext carries state needed to persist generated codes.
type saveRecoveryCodesContext struct {
	mgr             cookie.Manager
	username        string
	stored          string
	sourceBackend   uint8
	remoteGenerated bool
}

type recoveryCodesPayload struct {
	Codes []string `json:"codes"`
}

// newSaveRecoveryCodesContext reads session state for saving recovery codes.
func newSaveRecoveryCodesContext(ctx *gin.Context) saveRecoveryCodesContext {
	context := saveRecoveryCodesContext{
		mgr:           cookie.GetManager(ctx),
		sourceBackend: uint8(definitions.BackendLDAP),
	}
	if context.mgr == nil {
		return context
	}

	context.username = context.mgr.GetString(definitions.SessionKeyAccount, "")
	context.sourceBackend = context.mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	context.stored = context.mgr.GetString(definitions.SessionKeyRecoveryCodes, "")
	context.remoteGenerated = context.mgr.GetBool(definitions.SessionKeyRecoveryCodesRemoteGenerated, false)

	return context
}

// validateSaveRecoveryContext checks whether a save request has session state.
func (h *FrontendHandler) validateSaveRecoveryContext(ctx *gin.Context, context saveRecoveryCodesContext) bool {
	if context.username == "" || (context.stored == "" && !context.remoteGenerated) {
		h.renderErrorModal(ctx, "Invalid request")

		return false
	}

	return true
}

// bindRecoveryCodesPayload decodes the submitted recovery-code confirmation.
func (h *FrontendHandler) bindRecoveryCodesPayload(ctx *gin.Context) (recoveryCodesPayload, bool) {
	var payload recoveryCodesPayload
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		h.renderErrorModal(ctx, "Invalid request")

		return payload, false
	}

	return payload, true
}

// recoveryCodesFromSession returns generated codes stored in the session.
func recoveryCodesFromSession(stored string) []string {
	if stored == "" {
		return nil
	}

	return strings.Split(stored, ",")
}

// validateRecoveryCodesPayload checks that local generated codes match the browser payload.
func (h *FrontendHandler) validateRecoveryCodesPayload(ctx *gin.Context, context saveRecoveryCodesContext, payload recoveryCodesPayload, storedCodes []string) bool {
	if !context.remoteGenerated && len(payload.Codes) > 0 && !slices.Equal(payload.Codes, storedCodes) {
		h.renderErrorModal(ctx, "Invalid request")

		return false
	}

	return true
}

// finishSaveRecoveryCodes updates cache and session state after successful save.
func (h *FrontendHandler) finishSaveRecoveryCodes(ctx *gin.Context, context saveRecoveryCodesContext) {
	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state != nil {
		state.PurgeCacheFor(context.username)
	}

	if context.mgr == nil {
		return
	}

	context.mgr.Delete(definitions.SessionKeyRecoveryCodes)
	context.mgr.Delete(definitions.SessionKeyRecoveryCodesRemoteGenerated)
	context.mgr.Set(definitions.SessionKeyRecoveryCodesSaved, true)
	context.mgr.Set(definitions.SessionKeyHaveRecoveryCodes, true)

	if context.mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		h.removeCompletedRequireMFAMethod(ctx, context.mgr, definitions.MFAMethodRecoveryCodes)
	}
}

// SaveRecoveryCodes persists the recovery codes once the user downloaded them.
func (h *FrontendHandler) SaveRecoveryCodes(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.save_recovery_codes")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	context := newSaveRecoveryCodesContext(ctx)
	if !h.validateSaveRecoveryContext(ctx, context) {
		return
	}

	payload, ok := h.bindRecoveryCodesPayload(ctx)
	if !ok {
		return
	}

	storedCodes := recoveryCodesFromSession(context.stored)
	if !h.validateRecoveryCodesPayload(ctx, context, payload, storedCodes) {
		return
	}

	if err := h.mfa.SaveRecoveryCodes(ctx, context.username, storedCodes, context.sourceBackend); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "recovery", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to save recovery codes", err)

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "recovery", "success").Inc()

	h.finishSaveRecoveryCodes(ctx, context)
	ctx.Status(http.StatusOK)
}

// recoveryCodesSavedOrPresent checks whether the user can continue past recovery setup.
func (h *FrontendHandler) recoveryCodesSavedOrPresent(ctx *gin.Context, mgr cookie.Manager, userData *UserBackendData) bool {
	if userData.NumRecoveryCodes > 0 {
		return true
	}

	saved := false
	if mgr != nil {
		saved = mgr.GetBool(definitions.SessionKeyRecoveryCodesSaved, false)
	}

	if !saved {
		h.renderErrorModal(ctx, "Recovery codes have not been saved")

		return false
	}

	return true
}

// continueAfterRecoveryRegistration redirects or resumes after recovery-code setup.
func (h *FrontendHandler) continueAfterRecoveryRegistration(ctx *gin.Context, mgr cookie.Manager) {
	if mgr != nil {
		mgr.Delete(definitions.SessionKeyRecoveryCodesSaved)
	}

	if mgr != nil && mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		h.removeCompletedRequireMFAMethod(ctx, mgr, definitions.MFAMethodRecoveryCodes)
		ctx.Redirect(http.StatusFound, definitions.MFARoot+"/register/continue")

		return
	}

	if mgr != nil && mgr.GetString(definitions.SessionKeyIDPFlowID, "") != "" {
		if h.checkRequireMFARegistrationAndRedirect(ctx, mgr) {
			return
		}

		h.resumeIDPFlow(ctx, mgr)

		return
	}

	if ctx.GetHeader("HX-Request") != "" {
		ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
		ctx.Status(http.StatusOK)

		return
	}

	ctx.Redirect(http.StatusFound, definitions.MFARoot+"/register/home")
}

// PostRegisterRecoveryCodes handles the continue action after recovery codes are saved.
func (h *FrontendHandler) PostRegisterRecoveryCodes(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_register_recovery_codes")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	mgr := cookie.GetManager(ctx)
	username := ""

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	if username == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Failed to fetch user data")

		return
	}

	if !h.recoveryCodesSavedOrPresent(ctx, mgr, userData) {
		return
	}

	h.continueAfterRecoveryRegistration(ctx, mgr)
}

// PostGenerateRecoveryCodes handles generating new recovery codes.
func (h *FrontendHandler) PostGenerateRecoveryCodes(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_generate_recovery_codes")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.enforceMFASelfServiceStepUp(ctx) {
		return
	}

	mgr := cookie.GetManager(ctx)
	username := ""
	sourceBackend := uint8(definitions.BackendLDAP)

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
		sourceBackend = mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	if username == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Failed to fetch user data")

		return
	}

	if !userData.HaveTOTP && !userData.HaveWebAuthn {
		h.renderErrorModal(ctx, "At least one MFA method (TOTP or WebAuthn) must be active to generate recovery codes")

		return
	}

	codes, err := h.mfa.GenerateRecoveryCodes(ctx, username, sourceBackend)
	if err != nil {
		sp.RecordError(err)
		h.renderErrorModalWithErr(ctx, "Failed to generate recovery codes", err)

		return
	}

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "recovery", "success").Inc()

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state != nil {
		state.PurgeCacheFor(username)
	}

	data := h.basePageData(ctx)
	data["NewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "New recovery codes")
	data["BackupTheseCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup these codes!")
	data["ShownOnlyOnce"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "They will be shown only once.")
	data["Copy"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Copy")
	data["CopiedToClipboard"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Copied to clipboard")
	data["Download"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Download")
	data["Downloaded"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Downloaded")
	data["Close"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Close")
	data["Codes"] = codes
	data["RecoveryHomeEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/register/home")

	ctx.HTML(http.StatusOK, "idp_recovery_codes_modal.html", data)
}

// DeleteTOTP removes TOTP for the user.
func (h *FrontendHandler) DeleteTOTP(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_totp")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.enforceMFASelfServiceStepUp(ctx) {
		return
	}

	mgr := cookie.GetManager(ctx)
	username := ""
	sourceBackend := uint8(definitions.BackendLDAP)

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
		sourceBackend = mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	if username == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	if err := h.mfa.DeleteTOTP(ctx, username, sourceBackend); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to delete TOTP secret", err)

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "success").Inc()

	if mgr != nil {
		mgr.Set(definitions.SessionKeyHaveTOTP, false)
	}

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state == nil {
		h.renderErrorModal(ctx, "Failed to initialize auth state")

		return
	}

	state.PurgeCacheFor(username)

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// deleteWebAuthnIdentity reads the current session identity for WebAuthn deletion.
func deleteWebAuthnIdentity(ctx *gin.Context) (string, string) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return "", ""
	}

	return mgr.GetString(definitions.SessionKeyUniqueUserID, ""), mgr.GetString(definitions.SessionKeyAccount, "")
}

// deleteWebAuthnCredentials removes every stored WebAuthn credential from the backend.
func deleteWebAuthnCredentials(userData *UserBackendData) error {
	if userData.WebAuthnUser == nil || len(userData.WebAuthnUser.Credentials) == 0 {
		return nil
	}

	for _, cred := range userData.WebAuthnUser.Credentials {
		credential := cred

		if err := userData.AuthState.DeleteWebAuthnCredential(&credential); err != nil {
			return err
		}
	}

	return nil
}

// DeleteWebAuthn removes WebAuthn credentials for the user.
func (h *FrontendHandler) DeleteWebAuthn(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_webauthn")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.enforceMFASelfServiceStepUp(ctx) {
		return
	}

	userID, username := deleteWebAuthnIdentity(ctx)
	if userID == "" || username == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil || userData.AuthState == nil {
		if err != nil {
			sp.RecordError(err)
		}

		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModal(ctx, "Failed to load user data")

		return
	}

	if err := deleteWebAuthnCredentials(userData); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to delete WebAuthn credential", err)

		return
	}

	// First, clear the Redis cache
	key := h.deps.Cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + userID
	if err := h.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), key).Err(); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to delete WebAuthn from Redis", err)

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "success").Inc()

	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Set(definitions.SessionKeyHaveWebAuthn, false)
	}

	userData.AuthState.PurgeCacheFor(username)

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// RegisterWebAuthn renders the WebAuthn registration page.
func (h *FrontendHandler) RegisterWebAuthn(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	if mgr == nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	if !h.restoreRequireMFAIdentityContextFromStore(ctx, mgr) {
		h.clearRequireMFARegistrationState(mgr)
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	uniqueUserID := mgr.GetString(definitions.SessionKeyUniqueUserID, "")
	if uniqueUserID == "" {
		// Defensive recovery: older/partial sessions can miss unique_userid even
		// when account is present. Try to reconstruct backend identity once.
		if userData, err := h.GetUserBackendData(ctx); err == nil && userData != nil && userData.UniqueUserID != "" {
			mgr.Set(definitions.SessionKeyUniqueUserID, userData.UniqueUserID)
			uniqueUserID = userData.UniqueUserID
		}
	}

	if uniqueUserID == "" {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	requireFlow := mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false)

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn")
	data["WebAuthnMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please connect your security key and follow the instructions")
	data["DeviceNameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device name")
	data["DeviceNamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "e.g. Office YubiKey")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	// JS Localizations
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingRegistration"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing registration...")
	data["JSDeviceNameRequired"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter a device name")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")
	data["CSRFToken"] = csrf.Token(ctx)
	data["WebAuthnBeginEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/register/begin")
	data["WebAuthnFinishEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/register/finish")

	webAuthnNextEndpoint := definitions.MFARoot + "/register/home"
	if requireFlow {
		webAuthnNextEndpoint = definitions.MFARoot + "/register/continue"
	}

	data["WebAuthnNextEndpoint"] = localizedMFARootPath(ctx, webAuthnNextEndpoint)

	data["RequireMFAFlow"] = requireFlow
	data["RequireMFAMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Your application requires this authentication method to be set up before you can continue")
	data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
	data["CancelMFAEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/register/cancel")

	ctx.HTML(http.StatusOK, "idp_webauthn_register.html", data)
}

// LoggedOut renders the logout confirmation page.
func (h *FrontendHandler) LoggedOut(ctx *gin.Context) {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logged Out")
	data["LoggedOutTitle"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Successfully Logged Out")
	data["LoggedOutMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You have been successfully logged out of your session.")
	data["BackToLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back to Login")

	ctx.HTML(http.StatusOK, "idp_logged_out.html", data)
}

func (h *FrontendHandler) renderErrorModal(ctx *gin.Context, msg string) {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Error")
	data["Message"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, msg)
	data["Close"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Close")

	ctx.HTML(http.StatusOK, "idp_error_modal.html", data)
}

// renderErrorModalWithErr renders an error modal that extracts details from
// DetailedError instances, showing a translatable message and technical details separately.
func (h *FrontendHandler) renderErrorModalWithErr(ctx *gin.Context, msg string, err error) {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Error")
	data["Message"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, msg)
	data["Close"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Close")

	if detailedErr, ok := stderrors.AsType[*errors.DetailedError](err); ok {
		if detail := detailedErr.GetDetails(); detail != "" {
			data["Detail"] = detail
		}
	}

	ctx.HTML(http.StatusOK, "idp_error_modal.html", data)
}

// WebAuthnDevices renders the WebAuthn devices overview page.
func (h *FrontendHandler) WebAuthnDevices(ctx *gin.Context) {
	data := h.basePageData(ctx)

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.handleTwoFAHomeError(ctx, data, err, "")

		return
	}

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Keys (WebAuthn)")
	data["RegisteredDevices"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Registered Devices")
	data["DeviceName"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device name")
	data["DeviceID"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device ID")
	data["NoDevicesFound"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "No registered security keys found.")
	data["LastUsed"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Last used")
	data["Never"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Never")
	data["Rename"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Rename")
	data["Save"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Save")
	data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
	data["Delete"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Delete")
	data["DeleteConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to delete this security key?")
	data["AddDevice"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Add new security key")
	data["BackTo2FA"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back to 2FA Overview")
	data["UnnamedDevice"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Unnamed device")
	data["BackTo2FAEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/register/home")
	data["AddDeviceEndpoint"] = localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/register")

	type device struct {
		Name           string
		ID             string
		LastUsed       string
		NameEndpoint   string
		DeleteEndpoint string
	}

	var devices []device

	if userData.WebAuthnUser != nil {
		for _, cred := range userData.WebAuthnUser.Credentials {
			name := strings.TrimSpace(cred.Name)

			lastUsed := data["Never"].(string)
			if !cred.LastUsed.IsZero() {
				lastUsed = cred.LastUsed.Format("2006-01-02 15:04:05")
			}

			encodedID := base64.RawURLEncoding.EncodeToString(cred.ID)
			devices = append(devices, device{
				Name:           name,
				ID:             encodedID,
				LastUsed:       lastUsed,
				NameEndpoint:   localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/device/"+encodedID+"/name"),
				DeleteEndpoint: localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/device/"+encodedID),
			})
		}
	}

	data["Devices"] = devices
	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_2fa_webauthn_devices.html", data)
}

// DeleteWebAuthnDevice removes a specific WebAuthn credential for the user.
func (h *FrontendHandler) DeleteWebAuthnDevice(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_webauthn_device")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.enforceMFASelfServiceStepUp(ctx) {
		return
	}

	decodedID, ok := h.webAuthnDeviceID(ctx)
	if !ok {
		return
	}

	userData, ok := h.webAuthnDeviceUserData(ctx)
	if !ok {
		return
	}

	targetIndex := findWebAuthnCredentialIndex(userData.WebAuthnUser, decodedID)
	if targetIndex == -1 {
		h.renderErrorModal(ctx, "Credential not found")

		return
	}

	targetCred := userData.WebAuthnUser.Credentials[targetIndex]
	if err := userData.AuthState.DeleteWebAuthnCredential(&targetCred); err != nil {
		sp.RecordError(err)
		h.renderErrorModalWithErr(ctx, "Failed to delete credential", err)

		return
	}

	if userData.UsesRemoteWebAuthnAuthority() {
		h.finishRemoteWebAuthnAuthorityChange(ctx, userData)

		return
	}

	h.finishLocalWebAuthnDeviceDelete(ctx, userData, targetIndex)
}

// webAuthnDeviceID decodes the URL credential ID for WebAuthn device mutations.
func (h *FrontendHandler) webAuthnDeviceID(ctx *gin.Context) ([]byte, bool) {
	id := ctx.Param("id")
	if id == "" {
		h.renderErrorModal(ctx, "Missing device ID")

		return nil, false
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		h.renderErrorModal(ctx, "Invalid device ID")

		return nil, false
	}

	return decodedID, true
}

// finishLocalWebAuthnDeviceDelete updates local cache state after deleting a credential.
func (h *FrontendHandler) finishLocalWebAuthnDeviceDelete(
	ctx *gin.Context,
	userData *UserBackendData,
	targetIndex int,
) {
	if len(userData.WebAuthnUser.Credentials) <= 1 {
		_ = h.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), webAuthnRedisUserKey(h.deps.Cfg, userData.UniqueUserID)).Err()
	} else {
		userData.WebAuthnUser.Credentials = slices.Delete(userData.WebAuthnUser.Credentials, targetIndex, targetIndex+1)
		_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, userData.WebAuthnUser, h.deps.Cfg.GetServer().GetTimeouts().GetRedisWrite())
	}

	userData.AuthState.PurgeCacheFor(userData.Username)
	redirectWebAuthnDevices(ctx)
}

// webAuthnRedisUserKey returns the Redis key for cached WebAuthn user data.
func webAuthnRedisUserKey(cfg config.File, uniqueUserID string) string {
	return cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserID
}

// UpdateWebAuthnDeviceName renames a specific WebAuthn credential for the user.
func (h *FrontendHandler) UpdateWebAuthnDeviceName(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.update_webauthn_device_name")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.enforceMFASelfServiceStepUp(ctx) {
		return
	}

	decodedID, name, ok := h.webAuthnDeviceNameUpdate(ctx)
	if !ok {
		return
	}

	userData, ok := h.webAuthnDeviceUserData(ctx)
	if !ok {
		return
	}

	targetIndex := findWebAuthnCredentialIndex(userData.WebAuthnUser, decodedID)
	if targetIndex == -1 {
		h.renderErrorModal(ctx, "Credential not found")

		return
	}

	oldCredential := userData.WebAuthnUser.Credentials[targetIndex]
	newCredential := oldCredential
	newCredential.Name = name

	if err := userData.AuthState.UpdateWebAuthnCredential(&oldCredential, &newCredential); err != nil {
		sp.RecordError(err)
		h.renderErrorModalWithErr(ctx, "Failed to update credential", err)

		return
	}

	if userData.UsesRemoteWebAuthnAuthority() {
		h.finishRemoteWebAuthnAuthorityChange(ctx, userData)

		return
	}

	h.finishLocalWebAuthnDeviceNameUpdate(ctx, userData, targetIndex, name)
}

// webAuthnDeviceNameUpdate validates form input for renaming a WebAuthn credential.
func (h *FrontendHandler) webAuthnDeviceNameUpdate(ctx *gin.Context) ([]byte, string, bool) {
	decodedID, ok := h.webAuthnDeviceID(ctx)
	if !ok {
		return nil, "", false
	}

	name := strings.TrimSpace(ctx.PostForm("name"))
	if name == "" {
		h.renderErrorModal(ctx, "Missing device name")

		return nil, "", false
	}

	return decodedID, name, true
}

// webAuthnDeviceUserData loads user backend data required by WebAuthn device mutations.
func (h *FrontendHandler) webAuthnDeviceUserData(ctx *gin.Context) (*UserBackendData, bool) {
	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Not logged in")

		return nil, false
	}

	if userData.WebAuthnUser == nil {
		h.renderErrorModal(ctx, "User not found")

		return nil, false
	}

	return userData, true
}

// findWebAuthnCredentialIndex returns the index of a credential by raw ID.
func findWebAuthnCredentialIndex(user *backend.User, decodedID []byte) int {
	return slices.IndexFunc(user.Credentials, func(credential mfa.PersistentCredential) bool {
		return bytes.Equal(credential.ID, decodedID)
	})
}

// finishLocalWebAuthnDeviceNameUpdate persists a local WebAuthn credential rename.
func (h *FrontendHandler) finishLocalWebAuthnDeviceNameUpdate(
	ctx *gin.Context,
	userData *UserBackendData,
	targetIndex int,
	name string,
) {
	userData.WebAuthnUser.Credentials[targetIndex].Name = name
	_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, userData.WebAuthnUser, h.deps.Cfg.GetServer().GetTimeouts().GetRedisWrite())

	userData.AuthState.PurgeCacheFor(userData.Username)
	redirectWebAuthnDevices(ctx)
}

// finishRemoteWebAuthnAuthorityChange invalidates local cache after an authority-owned mutation.
func (h *FrontendHandler) finishRemoteWebAuthnAuthorityChange(ctx *gin.Context, userData *UserBackendData) {
	_ = backend.DeleteWebAuthnFromRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, userData.UniqueUserID)
	userData.AuthState.PurgeCacheFor(userData.Username)
	redirectWebAuthnDevices(ctx)
}

// redirectWebAuthnDevices returns HTMX callers to the WebAuthn device list.
func redirectWebAuthnDevices(ctx *gin.Context) {
	ctx.Header("HX-Redirect", definitions.MFARoot+"/webauthn/devices")
	ctx.Status(http.StatusOK)
}
