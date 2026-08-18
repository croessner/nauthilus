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
	"time"

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
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/v3/server/middleware/lua"
	"github.com/croessner/nauthilus/v3/server/middleware/securityheaders"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

const canonicalAuthenticatedViewContextKey = "canonical_authenticated_view"

const (
	webAuthnDeviceNameMaxRunes    = 64
	canonicalLoginErrorContextKey = "canonical_login_error"
	notLoggedInMessage            = "Not logged in"
)

// FrontendHandler handles general IDP frontend pages like login and consent.
type FrontendHandler struct {
	deps                                  *deps.Deps
	canonicalRuntime                      *cookie.CanonicalRuntime
	canonicalPasswordAuthenticator        canonicalPasswordAuthenticator
	deviceStore                           idp.DeviceCodeStore
	canonicalEnrollmentResolver           canonicalEnrollmentResolver
	canonicalMFAAvailabilityResolver      canonicalMFAAvailabilityResolver
	canonicalTOTPVerifier                 canonicalTOTPVerifier
	canonicalRecoveryVerifier             canonicalRecoveryVerifier
	canonicalWebAuthnBegin                canonicalWebAuthnBegin
	canonicalWebAuthnFinish               canonicalWebAuthnFinish
	canonicalTOTPEnrollmentStarter        canonicalTOTPEnrollmentStarter
	canonicalTOTPEnrollmentFinisher       canonicalTOTPEnrollmentFinisher
	canonicalRecoveryEnrollmentGenerator  canonicalRecoveryEnrollmentGenerator
	canonicalRecoveryEnrollmentSaver      canonicalRecoveryEnrollmentSaver
	canonicalWebAuthnEnrollmentBegin      canonicalWebAuthnEnrollmentBegin
	canonicalWebAuthnEnrollmentFinish     canonicalWebAuthnEnrollmentFinish
	canonicalSelfServiceRename            canonicalSelfServiceRename
	canonicalSelfServiceBackendResolver   canonicalSelfServiceBackendResolver
	canonicalSelfServiceTOTPDeleter       canonicalSelfServiceTOTPDeleter
	canonicalSelfServiceRecoveryGenerator canonicalSelfServiceRecoveryGenerator
	canonicalWebAuthnCredentialDelete     func(*core.AuthState, *mfa.PersistentCredential) error
	canonicalWebAuthnCredentialUpdate     func(*core.AuthState, *mfa.PersistentCredential, *mfa.PersistentCredential) error
	tracer                                monittrace.Tracer
}

// NewCanonicalFrontendHandler binds the sole canonical runtime explicitly.
func NewCanonicalFrontendHandler(d *deps.Deps, runtime *cookie.CanonicalRuntime) (*FrontendHandler, error) {
	if d == nil || d.Cfg == nil || d.Env == nil || runtime == nil {
		return nil, stderrors.New("canonical frontend: missing required dependency")
	}

	handler := NewFrontendHandler(d)
	handler.canonicalRuntime = runtime

	return handler, nil
}

type canonicalEnrollmentResolver func(
	*gin.Context,
	*cookie.CanonicalSession,
	*flowdomain.State,
	cookie.SessionIdentity,
	[]string,
) ([]string, error)

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
		deviceStore: idp.NewRedisDeviceCodeStoreWithConfig(d.Redis, prefix, d.Cfg),
		tracer:      monittrace.New("nauthilus/idp/frontend"),
	}
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

// canonicalIDPFlow resolves and validates exactly one typed flow selected by the canonical request ticket.
func (h *FrontendHandler) canonicalIDPFlow(ctx *gin.Context) (*flowdomain.State, bool) {
	session := cookie.GetCanonicalSession(ctx)

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if session == nil || err != nil {
		return nil, false
	}

	state, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(ctx.Request.Context(), string(ticket))
	if err != nil {
		return nil, false
	}

	valid := false

	switch state.Protocol {
	case flowdomain.FlowProtocolOIDC:
		valid = validCanonicalOIDCLoginFlow(state)
	case flowdomain.FlowProtocolSAML:
		valid = validCanonicalSAMLLoginFlow(state)
	}

	return state, valid
}

// isValidIDPFlow reports whether the request resolves to one valid canonical protocol flow.
func (h *FrontendHandler) isValidIDPFlow(ctx *gin.Context) bool {
	_, valid := h.canonicalIDPFlow(ctx)

	return valid
}

func validCanonicalOIDCLoginFlow(state *flowdomain.State) bool {
	if state == nil || state.Protocol != flowdomain.FlowProtocolOIDC || state.Metadata == nil {
		return false
	}

	switch state.Type {
	case flowdomain.FlowTypeOIDCAuthorization:
		return state.Metadata[flowdomain.FlowMetadataClientID] != "" &&
			state.Metadata[flowdomain.FlowMetadataRedirectURI] != "" &&
			state.Metadata[flowdomain.FlowMetadataResponseType] != ""
	case flowdomain.FlowTypeOIDCDeviceCode:
		return state.Metadata[flowdomain.FlowMetadataClientID] != "" &&
			state.Metadata[flowdomain.FlowMetadataDeviceCode] != ""
	default:
		return false
	}
}

func validCanonicalSAMLLoginFlow(state *flowdomain.State) bool {
	return state != nil && state.Type == flowdomain.FlowTypeSAML &&
		state.Protocol == flowdomain.FlowProtocolSAML &&
		state.Metadata[flowdomain.FlowMetadataSAMLEntityID] != "" &&
		state.Metadata[flowdomain.FlowMetadataOriginalURL] != ""
}

// frontendErrorPage describes one browser-safe frontend error response.
type frontendErrorPage struct {
	code    string
	title   string
	message string
	status  int
}

// renderFrontendError renders a localized browser error with a JSON fallback.
func (h *FrontendHandler) renderFrontendError(ctx *gin.Context, page frontendErrorPage) {
	if h.deps == nil || h.deps.Cfg == nil {
		ctx.AbortWithStatusJSON(page.status, gin.H{
			frontChannelLogoutTaskStatusError: page.code,
			"message":                         page.message,
		})

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Error")
	data["ErrorTitle"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, page.title)
	data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, page.message)

	ctx.HTML(page.status, "idp_error.html", data)
}

// renderNoFlowError renders an error page when /login has no valid IDP flow.
func (h *FrontendHandler) renderNoFlowError(ctx *gin.Context) {
	h.renderFrontendError(ctx, frontendErrorPage{
		code:    "invalid_request",
		title:   "Invalid Request",
		message: "This login page can only be accessed through a valid OIDC or SAML2 authentication flow. Please use your application to initiate the login process.",
		status:  http.StatusBadRequest,
	})
}

// renderExpiredSelfServiceSessionError explains how to restart self-service safely.
func (h *FrontendHandler) renderExpiredSelfServiceSessionError(ctx *gin.Context) {
	h.renderFrontendError(ctx, frontendErrorPage{
		code:    "self_service_session_expired",
		title:   "Session Expired",
		message: "Your self-service session has expired. Please sign in again through your application and reopen the 2FA self-service.",
		status:  http.StatusUnauthorized,
	})
}

// Register adds frontend routes using only the canonical browser-session boundary.
func (h *FrontendHandler) Register(router gin.IRouter) {
	registerFrontendStaticAssets(router, h.frontendAssetBase())
	registerIDPContextMiddleware(router)

	middlewares := h.newFrontendRouteMiddlewares()
	h.registerLoginRoutes(router, middlewares, frontendRouteHandlers)
	h.registerAuthRoutes(router, middlewares, frontendAuthRouteHandlers, h.CanonicalAuthMiddleware())
	h.registerLoggedOutRoutes(router, middlewares)
}

type frontendRouteMiddlewares struct {
	security  gin.HandlerFunc
	csrf      gin.HandlerFunc
	canonical gin.HandlerFunc
	i18n      gin.HandlerFunc
}

type frontendRouteChain func(frontendRouteMiddlewares, gin.HandlerFunc) []gin.HandlerFunc

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
	csrfMiddleware := csrf.NewHandler(csrf.WithBaseCookie(http.Cookie{
		MaxAge: csrf.MaxAge, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: !h.deps.Env.GetDevMode(), Path: "/",
	})).Middleware()

	return frontendRouteMiddlewares{
		security:  securityheaders.New(securityheaders.MiddlewareConfig{Config: h.deps.Cfg}).Handler(),
		csrf:      csrfMiddleware,
		canonical: cookie.CanonicalMiddleware(h.canonicalRuntime, cookie.CanonicalContinuation),
		i18n: i18n.WithLanguageCookieSecurity(
			h.deps.Cfg, h.deps.Logger, h.deps.LangManager, !h.deps.Env.GetDevMode(),
		),
	}
}

// frontendRouteHandlers builds the canonical browser-session chain without legacy cookie middleware.
func frontendRouteHandlers(middlewares frontendRouteMiddlewares, handler gin.HandlerFunc) []gin.HandlerFunc {
	return []gin.HandlerFunc{middlewares.security, middlewares.canonical, middlewares.csrf, middlewares.i18n, handler}
}

// frontendAuthRouteHandlers builds the authenticated canonical self-service chain.
func frontendAuthRouteHandlers(middlewares frontendRouteMiddlewares, auth gin.HandlerFunc) []gin.HandlerFunc {
	return []gin.HandlerFunc{middlewares.security, middlewares.canonical, middlewares.csrf, middlewares.i18n, auth}
}

// frontendCookieFreeRouteHandlers builds a chain that does not write the secure session cookie.
func frontendCookieFreeRouteHandlers(middlewares frontendRouteMiddlewares, handler gin.HandlerFunc) []gin.HandlerFunc {
	return []gin.HandlerFunc{middlewares.security, middlewares.csrf, middlewares.i18n, handler}
}

// registerLoginRoutes registers login, MFA challenge, and recovery-code login routes.
func (h *FrontendHandler) registerLoginRoutes(
	router gin.IRouter,
	middlewares frontendRouteMiddlewares,
	routeHandlers frontendRouteChain,
) {
	router.GET(frontendLoginPath, routeHandlers(middlewares, h.Login)...)
	router.GET("/login/:languageTag", routeHandlers(middlewares, h.Login)...)
	router.POST(frontendLoginPath, routeHandlers(middlewares, h.PostLogin)...)
	router.POST("/login/:languageTag", routeHandlers(middlewares, h.PostLogin)...)
	router.GET("/login/totp", routeHandlers(middlewares, h.LoginTOTP)...)
	router.GET("/login/totp/:languageTag", routeHandlers(middlewares, h.LoginTOTP)...)
	router.POST("/login/totp", routeHandlers(middlewares, h.PostLoginTOTP)...)
	router.POST("/login/totp/:languageTag", routeHandlers(middlewares, h.PostLoginTOTP)...)
	router.GET("/login/webauthn", routeHandlers(middlewares, h.LoginWebAuthn)...)
	router.GET("/login/webauthn/:languageTag", routeHandlers(middlewares, h.LoginWebAuthn)...)
	router.GET("/login/webauthn/begin", routeHandlers(middlewares, h.LoginWebAuthnBegin)...)
	router.GET("/login/webauthn/begin/:languageTag", routeHandlers(middlewares, h.LoginWebAuthnBegin)...)
	router.POST("/login/webauthn/finish", routeHandlers(middlewares, h.PostLoginWebAuthnFinish)...)
	router.POST("/login/webauthn/finish/:languageTag", routeHandlers(middlewares, h.PostLoginWebAuthnFinish)...)
	router.GET("/login/mfa", routeHandlers(middlewares, h.LoginMFASelect)...)
	router.GET("/login/mfa/:languageTag", routeHandlers(middlewares, h.LoginMFASelect)...)
	router.GET("/login/recovery", routeHandlers(middlewares, h.LoginRecovery)...)
	router.GET("/login/recovery/:languageTag", routeHandlers(middlewares, h.LoginRecovery)...)
	router.POST("/login/recovery", routeHandlers(middlewares, h.PostLoginRecovery)...)
	router.POST("/login/recovery/:languageTag", routeHandlers(middlewares, h.PostLoginRecovery)...)
}

// registerAuthRoutes registers protected MFA self-service routes.
func (h *FrontendHandler) registerAuthRoutes(
	router gin.IRouter,
	middlewares frontendRouteMiddlewares,
	routeHandlers frontendRouteChain,
	auth gin.HandlerFunc,
) {
	authGroup := router.Group(definitions.MFARoot, routeHandlers(middlewares, auth)...)

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
	router.GET("/webauthn/register", h.RegisterWebAuthn)
	router.GET("/webauthn/register/:languageTag", h.RegisterWebAuthn)
	router.GET("/webauthn/register/begin", h.BeginWebAuthnRegistration)
	router.GET("/webauthn/register/begin/:languageTag", h.BeginWebAuthnRegistration)
	router.POST("/webauthn/register/finish", h.FinishWebAuthnRegistration)
	router.POST("/webauthn/register/finish/:languageTag", h.FinishWebAuthnRegistration)
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
	router.GET("/self-service/continue", h.ContinueMFASelfServiceStepUp)
	router.GET("/self-service/continue/:languageTag", h.ContinueMFASelfServiceStepUp)
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

// CanonicalAuthMiddleware requires one authenticated typed browser session for protected self-service routes.
func (h *FrontendHandler) CanonicalAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := cookie.GetCanonicalSession(ctx)
		if session == nil {
			h.renderExpiredSelfServiceSessionError(ctx)
			ctx.Abort()

			return
		}

		if _, authenticated := session.Identity(); !authenticated {
			h.renderExpiredSelfServiceSessionError(ctx)
			ctx.Abort()

			return
		}

		ctx.Set(canonicalAuthenticatedViewContextKey, true)
		ctx.Next()
	}
}

func (h *FrontendHandler) basePageData(ctx *gin.Context) gin.H {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)

	data["DevMode"] = h.deps.Env.GetDevMode()
	data["HXRequest"] = ctx.GetHeader("HX-Request") != ""
	if ticket, err := flowdomain.TicketFromRequest(ctx.Request); err == nil {
		data["FlowTicket"] = string(ticket)
	}

	return data
}

func (h *FrontendHandler) setLoginRememberData(ctx *gin.Context, data gin.H, oidcCID, samlEntityID string) {
	data["ShowRememberMe"] = h.shouldShowRememberMe(oidcCID, samlEntityID)
	data["RememberMeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Remember me")
}

// BasePageData returns the common data for all IDP frontend pages.
func BasePageData(ctx *gin.Context, cfg config.File, langManager corelang.Manager) gin.H {
	return basePageDataForSession(ctx, cfg, langManager, basePageSessionDataFromContext(ctx))
}

func canonicalBasePageData(
	ctx *gin.Context,
	cfg config.File,
	langManager corelang.Manager,
	identity cookie.SessionIdentity,
	flowType string,
	oidcClientID string,
	samlEntityID string,
) gin.H {
	return basePageDataForSession(ctx, cfg, langManager, basePageSessionData{
		username: identity.Account, flowType: flowType,
		oidcClientID: oidcClientID, samlEntityID: samlEntityID,
	})
}

func basePageDataForSession(
	ctx *gin.Context,
	cfg config.File,
	langManager corelang.Manager,
	sessionData basePageSessionData,
) gin.H {
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

// basePageSessionDataFromContext extracts only the canonical session identity.
func basePageSessionDataFromContext(ctx *gin.Context) basePageSessionData {
	if ctx == nil || !ctx.GetBool(canonicalAuthenticatedViewContextKey) {
		return basePageSessionData{}
	}

	session := cookie.GetCanonicalSession(ctx)
	if session == nil {
		return basePageSessionData{}
	}

	identity, authenticated := session.Identity()
	if !authenticated {
		return basePageSessionData{}
	}

	return basePageSessionData{username: identity.Account}
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
// The opaque URL ticket selects server-side flow state bound to the canonical browser session.
func (h *FrontendHandler) Login(ctx *gin.Context) {
	protocolState, valid := h.canonicalIDPFlow(ctx)
	if !valid {
		h.renderNoFlowError(ctx)

		return
	}

	flowState := h.loginFlowState(protocolState)

	if h.resumeCanonicalExistingLoginSession(ctx, cookie.GetCanonicalSession(ctx), protocolState) {
		return
	}

	if flowState.grantType == definitions.OIDCFlowDeviceCode {
		ctx.Redirect(http.StatusFound, h.deviceVerifyPath(ctx))

		return
	}

	h.renderLoginPage(ctx, flowState)
}

type loginFlowState struct {
	flowType     string
	grantType    string
	oidcCID      string
	samlEntityID string
}

// loginFlowState extracts page-safe identifiers from one typed protocol record.
func (h *FrontendHandler) loginFlowState(state *flowdomain.State) loginFlowState {
	if state == nil {
		return loginFlowState{}
	}

	return loginFlowState{
		flowType:     string(state.Protocol),
		grantType:    state.GrantType,
		oidcCID:      state.Metadata[flowdomain.FlowMetadataClientID],
		samlEntityID: state.Metadata[flowdomain.FlowMetadataSAMLEntityID],
	}
}

// resumeCanonicalExistingLoginSession applies enrollment and assurance policy before typed protocol resume.
//
//nolint:gocyclo // Existing-login resume owns the complete enrollment, assurance, and protocol continuation decision.
func (h *FrontendHandler) resumeCanonicalExistingLoginSession(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
) bool {
	if h == nil || ctx == nil || session == nil || state == nil {
		return false
	}

	identity, authenticated := session.Identity()
	if !authenticated {
		return false
	}

	policy, ok := h.canonicalFlowMFAPolicy(ctx.Request.Context(), state)
	if !ok {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return true
	}

	missing, ok := h.canonicalMissingEnrollment(ctx, session, state, identity, policy.required)
	if !ok {
		return true
	}

	satisfied := canonicalSessionSatisfiesMFAPolicy(session, policy, session.EvaluationTime())
	if canonicalPromptNone(state) && (len(missing) > 0 || !satisfied) {
		redirectOIDCAuthorizeError(
			ctx,
			state.Metadata[flowdomain.FlowMetadataRedirectURI],
			state.Metadata[flowdomain.FlowMetadataState],
			"interaction_required",
		)

		return true
	}

	if len(missing) > 0 {
		if !h.startCanonicalRequiredMFAEnrollment(ctx, session, state, identity, missing) && !ctx.Writer.Written() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return true
	}

	if !satisfied {
		if !h.startCanonicalMFAAssuranceStepUp(ctx, session, state, identity, policy) && !ctx.Writer.Written() {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return true
	}

	if !h.resumeCanonicalIDPFlow(ctx, session, state) && !ctx.Writer.Written() {
		ctx.AbortWithStatus(http.StatusConflict)
	}

	return true
}

func (h *FrontendHandler) canonicalMissingEnrollment(
	ctx *gin.Context,
	session *cookie.CanonicalSession,
	state *flowdomain.State,
	identity cookie.SessionIdentity,
	required []string,
) ([]string, bool) {
	if len(required) == 0 {
		return nil, true
	}

	resolver := h.canonicalEnrollmentResolver
	if resolver == nil {
		resolver = h.canonicalMissingRequiredMFA
	}

	missing, err := resolver(ctx, session, state, identity, required)
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return nil, false
	}

	return missing, true
}

func canonicalPromptNone(state *flowdomain.State) bool {
	return state != nil && state.Protocol == flowdomain.FlowProtocolOIDC &&
		strings.TrimSpace(state.Metadata[flowdomain.FlowMetadataPrompt]) == oidcClientAuthMethodNone
}

// webAuthnFinishResponse is returned to browser JavaScript after a successful
// WebAuthn login assertion. Redirect stays server-derived so the client never
// reconstructs IDP flow state.
type webAuthnFinishResponse struct {
	Redirect string `json:"redirect"`
}

// renderLoginPage renders the initial username/password login page.
func (h *FrontendHandler) renderLoginPage(ctx *gin.Context, flowState loginFlowState) {
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
	h.applyLoginErrorData(ctx, data)
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

// applyLoginErrorData exposes only an error produced in the current request.
func (h *FrontendHandler) applyLoginErrorData(ctx *gin.Context, data gin.H) {
	loginError, _ := ctx.Get(canonicalLoginErrorContextKey)

	message, _ := loginError.(string)
	if message != "" {
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, message)

		return
	}

	data["HaveError"] = false
	data["ErrorMessage"] = ""
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

// postLoginFlowContext carries IDP flow state required for login.
type postLoginFlowContext struct {
	session      *cookie.CanonicalSession
	state        *flowdomain.State
	flowType     string
	grantType    string
	oidcCID      string
	samlEntityID string
	protocol     string
}

// postLoginCredentials carries submitted login credentials.
type postLoginCredentials struct {
	username      string
	password      string
	rememberMeTTL int
}

type canonicalPasswordAuthentication struct {
	user             *backend.User
	backendRef       core.RemoteBackendRef
	availableMethods []string
}

type canonicalPasswordAuthenticator func(
	*gin.Context,
	postLoginFlowContext,
	postLoginCredentials,
) (canonicalPasswordAuthentication, error)

func (h *FrontendHandler) authenticateCanonicalPassword(
	ctx *gin.Context,
	flowContext postLoginFlowContext,
	credentials postLoginCredentials,
) (canonicalPasswordAuthentication, error) {
	if h.canonicalPasswordAuthenticator != nil {
		return h.canonicalPasswordAuthenticator(ctx, flowContext, credentials)
	}

	result, err := idp.NewNauthilusIDP(h.deps).AuthenticateWithBackend(
		ctx, credentials.username, credentials.password, flowContext.oidcCID, flowContext.samlEntityID,
		core.IDPRequestContext{
			GrantType:       flowContext.grantType,
			RedirectURI:     flowContext.state.Metadata[flowdomain.FlowMetadataRedirectURI],
			RequestedScopes: strings.Fields(flowContext.state.Metadata[flowdomain.FlowMetadataScope]),
		},
	)

	return canonicalPasswordAuthentication{
		user: result.User, backendRef: result.BackendRef,
		availableMethods: h.canonicalPasswordMFAMethods(result.User),
	}, err
}

func (h *FrontendHandler) canonicalPasswordMFAMethods(user *backend.User) []string {
	methods := make([]string, 0, 3)
	if h.hasTOTP(user) {
		methods = append(methods, definitions.MFAMethodTOTP)
	}

	if user != nil && len(user.Credentials) > 0 {
		methods = append(methods, definitions.MFAMethodWebAuthn)
	}

	if h.hasRecoveryCodes(user) {
		methods = append(methods, definitions.MFAMethodRecoveryCodes)
	}

	return methods
}

// readPostLoginFlowContext composes request services with one typed protocol record.
func (h *FrontendHandler) readPostLoginFlowContext(ctx *gin.Context, state *flowdomain.State) postLoginFlowContext {
	result := postLoginFlowContextFromState(state)
	result.session = cookie.GetCanonicalSession(ctx)
	result.state = state

	return result
}

// postLoginFlowContextFromState maps typed protocol state into first-factor login inputs.
func postLoginFlowContextFromState(state *flowdomain.State) postLoginFlowContext {
	result := postLoginFlowContext{protocol: definitions.ProtoIDP}
	if state == nil {
		return result
	}

	result.flowType = string(state.Protocol)
	result.grantType = state.GrantType
	result.oidcCID = state.Metadata[flowdomain.FlowMetadataClientID]
	result.samlEntityID = state.Metadata[flowdomain.FlowMetadataSAMLEntityID]
	result.protocol = string(state.Protocol)

	return result
}

// isDeviceCodeLoginFlow reports whether login must continue via device verification.
func (context postLoginFlowContext) isDeviceCodeLoginFlow() bool {
	return context.flowType == definitions.ProtoOIDC &&
		context.grantType == definitions.OIDCFlowDeviceCode
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

func (h *FrontendHandler) handleCanonicalPostLoginAuthFailure(
	ctx *gin.Context,
	sp trace.Span,
	flowContext postLoginFlowContext,
	authentication canonicalPasswordAuthentication,
	err error,
) {
	sp.RecordError(err)
	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

	idpInstance := idp.NewNauthilusIDP(h.deps)
	if !idpAuthFailureAllowsDelayedResponse(err) ||
		!idpInstance.IsDelayedResponse(flowContext.oidcCID, flowContext.samlEntityID) ||
		authentication.user == nil {
		h.renderDetailedPostLoginFailure(ctx, flowContext, err)

		return
	}

	policy, ok := h.canonicalFlowMFAPolicy(ctx.Request.Context(), flowContext.state)
	if !ok {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return
	}

	availability := filterCanonicalMFAAvailability(mfaAvailability{
		haveTOTP:          slices.Contains(authentication.availableMethods, definitions.MFAMethodTOTP),
		haveWebAuthn:      slices.Contains(authentication.availableMethods, definitions.MFAMethodWebAuthn),
		haveRecoveryCodes: slices.Contains(authentication.availableMethods, definitions.MFAMethodRecoveryCodes),
	}, policy.supported)
	if availability.count == 0 {
		h.renderDetailedPostLoginFailure(ctx, flowContext, err)

		return
	}

	if !h.startCanonicalFailLatchedStepUp(ctx, flowContext, authentication, availability, policy) &&
		!ctx.Writer.Written() {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)
	}
}

//nolint:gocyclo,funlen // Delayed failure publication binds parent outcome, pending identity, affinity, and factor challenge.
func (h *FrontendHandler) startCanonicalFailLatchedStepUp(
	ctx *gin.Context,
	flowContext postLoginFlowContext,
	authentication canonicalPasswordAuthentication,
	availability mfaAvailability,
	policy canonicalMFAPolicy,
) bool {
	if ctx == nil || flowContext.session == nil || flowContext.state == nil || authentication.user == nil ||
		availability.count == 0 || policy.scope == "" {
		return false
	}

	if err := flowContext.state.UpdateAuthOutcome(flowdomain.AuthOutcomeFailLatched); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	flowContext.state.PendingMFA = true
	if err := flowdomain.NewTypedStore(
		flowContext.session.Stores, flowContext.session.Handle, flowContext.state.Protocol, canonicalStepUpTTL,
	).Save(ctx.Request.Context(), flowContext.state); err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return false
	}

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	user := authentication.user

	record := &sessionstate.StepUpRecord{
		Record: sessionstate.Record{Handle: handle}, Session: flowContext.session.Handle,
		Flow: sessionstate.Handle(flowContext.state.FlowID), AuthOutcome: string(flowdomain.AuthOutcomeFailLatched),
		PendingIdentityReference: user.ID,
		PendingIdentity: sessionstate.IdentitySummary{
			Account: user.Name, Subject: user.ID, DisplayName: user.DisplayName, Protocol: flowContext.protocol,
		},
		RequestedLevel: max(policy.requiredLevel, 1), Scope: policy.scope,
		SupportedMethods: canonicalAvailabilityMethods(availability),
	}
	if !authentication.backendRef.IsZero() {
		record.PendingBackendAffinity = sessionstate.BackendAffinitySummary{
			Type: authentication.backendRef.Type, Name: authentication.backendRef.Name,
			Protocol: authentication.backendRef.Protocol, Authority: authentication.backendRef.Authority,
			OpaqueToken: authentication.backendRef.OpaqueToken,
		}
	}

	if err = mfastate.NewAggregate(flowContext.session.Stores, flowContext.session.Handle, canonicalStepUpTTL).
		BeginStepUp(ctx.Request.Context(), record); err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	target := h.getMFASelectPath(ctx)
	if direct, ok := h.getMFARedirectURLFromAvailability(availability); ok {
		target = direct
	}

	ctx.Redirect(http.StatusFound, flowdomain.AppendTicket(target, string(handle)))

	return true
}

func canonicalAvailabilityMethods(availability mfaAvailability) []string {
	methods := make([]string, 0, availability.count)
	if availability.haveTOTP {
		methods = append(methods, definitions.MFAMethodTOTP)
	}

	if availability.haveWebAuthn {
		methods = append(methods, definitions.MFAMethodWebAuthn)
	}

	if availability.haveRecoveryCodes {
		methods = append(methods, definitions.MFAMethodRecoveryCodes)
	}

	return methods
}

// storeSuccessfulPostLoginSession persists the completed first-factor login.
func (h *FrontendHandler) storeSuccessfulPostLoginSession(
	ctx *gin.Context,
	flowContext postLoginFlowContext,
	credentials postLoginCredentials,
	user *backend.User,
	backendRef core.RemoteBackendRef,
) bool {
	if ctx == nil || flowContext.session == nil || flowContext.state == nil || user == nil {
		if ctx != nil {
			ctx.AbortWithStatus(http.StatusServiceUnavailable)
		}

		return false
	}

	var affinity *cookie.SessionBackendAffinity
	if !backendRef.IsZero() {
		affinity = &cookie.SessionBackendAffinity{
			Type: backendRef.Type, Name: backendRef.Name, Protocol: backendRef.Protocol,
			Authority: backendRef.Authority, OpaqueToken: backendRef.OpaqueToken,
		}
	}

	rotated, err := flowContext.session.CompleteLogin(ctx.Request.Context(), ctx.Writer, cookie.LoginCompletionInput{
		Identity: cookie.IdentityUpdate{
			Reference: user.ID, Account: user.Name, Subject: user.ID, DisplayName: user.DisplayName,
			Protocol: flowContext.protocol, BackendAffinity: affinity,
		},
		Flow: sessionstate.Handle(flowContext.state.FlowID), Protocol: flowContext.protocol,
		NextStep:    string(flowdomain.FlowStepLogin),
		RememberTTL: time.Duration(credentials.rememberMeTTL) * time.Second,
	})
	if err != nil {
		ctx.AbortWithStatus(http.StatusServiceUnavailable)

		return false
	}

	cookie.SetCanonicalSession(ctx, rotated)

	if h != nil && h.deps != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(), h.deps.Cfg, h.deps.Logger, definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Login successful - canonical session committed",
		)
	}

	return true
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

	protocolState, valid := h.canonicalIDPFlow(ctx)
	if !valid {
		h.renderNoFlowError(ctx)

		return
	}

	flowContext := h.readPostLoginFlowContext(ctx, protocolState)
	if flowContext.isDeviceCodeLoginFlow() {
		ctx.Redirect(http.StatusFound, h.deviceVerifyPath(ctx))

		return
	}

	credentials := h.readPostLoginCredentials(ctx, flowContext)
	h.logPostLoginAttempt(ctx, flowContext, credentials)

	annotatePostLoginSpan(sp, flowContext, credentials)

	authentication, err := h.authenticateCanonicalPassword(ctx, flowContext, credentials)
	if err != nil {
		h.handleCanonicalPostLoginAuthFailure(ctx, sp, flowContext, authentication, err)

		return
	}

	if !h.storeSuccessfulPostLoginSession(
		ctx, flowContext, credentials, authentication.user, authentication.backendRef,
	) {
		return
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	if !h.resumeCanonicalExistingLoginSession(ctx, cookie.GetCanonicalSession(ctx), flowContext.state) &&
		!ctx.Writer.Written() {
		ctx.AbortWithStatus(http.StatusConflict)
	}
}

// PostLoginWebAuthnFinish completes WebAuthn MFA and returns the server-derived
// continuation target for the surrounding IDP flow.
func (h *FrontendHandler) PostLoginWebAuthnFinish(ctx *gin.Context) {
	h.completeCanonicalWebAuthn(ctx)
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

// LoginMFASelect renders the MFA selection page from one typed step-up ticket.
func (h *FrontendHandler) LoginMFASelect(ctx *gin.Context) {
	selection, err := h.canonicalMFASelection(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	if redirectURL, ok := h.getMFARedirectURLFromAvailability(selection.availability); ok {
		ctx.Redirect(http.StatusFound, currentFlowTicketURL(ctx, localizedLoginPath(ctx, redirectURL)))

		return
	}

	backURL, ok := canonicalMFASelectionBackURL(ctx, selection)
	if !ok {
		ctx.AbortWithStatus(http.StatusConflict)

		return
	}

	ctx.HTML(http.StatusOK, "idp_mfa_select.html", h.loginMFASelectPageData(ctx, selection.availability, backURL))
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
func (h *FrontendHandler) loginMFASelectPageData(
	ctx *gin.Context,
	availability mfaAvailability,
	backURL string,
) gin.H {
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
	data["TOTPLoginEndpoint"] = currentFlowTicketURL(ctx, localizedLoginPath(ctx, "/login/totp"))
	data["WebAuthnLoginEndpoint"] = currentFlowTicketURL(ctx, localizedLoginPath(ctx, "/login/webauthn"))
	data["RecoveryLoginEndpoint"] = currentFlowTicketURL(ctx, localizedLoginPath(ctx, "/login/recovery"))

	lastMFA, recommendedMethod := recommendedMFAMethod(ctx, availability)

	data["LastMFAMethod"] = lastMFA
	data["RecommendedMethod"] = recommendedMethod
	data["HasOtherMethods"] = hasOtherMFAMethods(availability, recommendedMethod)
	data["OtherMethods"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Other methods")
	data["BackURL"] = backURL

	return data
}

func currentFlowTicketURL(ctx *gin.Context, target string) string {
	if ctx == nil {
		return target
	}

	ticket, err := flowdomain.TicketFromRequest(ctx.Request)
	if err != nil {
		return target
	}

	return flowdomain.AppendTicket(target, string(ticket))
}

// LoginRecovery renders the recovery code verification page from one typed step-up ticket.
func (h *FrontendHandler) LoginRecovery(ctx *gin.Context) {
	h.renderCanonicalRecovery(ctx, false)
}

// PostLoginRecovery consumes one recovery code and completes one typed step-up.
func (h *FrontendHandler) PostLoginRecovery(ctx *gin.Context) {
	h.completeCanonicalRecovery(ctx)
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

// LoginWebAuthn renders the WebAuthn verification page from one typed step-up ticket.
func (h *FrontendHandler) LoginWebAuthn(ctx *gin.Context) {
	h.renderCanonicalWebAuthn(ctx)
}

// LoginTOTP renders the TOTP verification page from one typed step-up ticket.
func (h *FrontendHandler) LoginTOTP(ctx *gin.Context) {
	h.renderCanonicalTOTP(ctx, false)
}

// PostLoginTOTP verifies TOTP against the canonical identity and completes one typed step-up.
func (h *FrontendHandler) PostLoginTOTP(ctx *gin.Context) {
	h.completeCanonicalTOTP(ctx)
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

	_, _, userData, _, err := h.canonicalSelfServiceBackend(ctx)
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
	h.renderCanonicalTOTPEnrollment(ctx)
}

// PostRegisterTOTP handles the TOTP registration submission.
func (h *FrontendHandler) PostRegisterTOTP(ctx *gin.Context) {
	h.completeCanonicalTOTPEnrollment(ctx)
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
	h.renderCanonicalRecoveryEnrollment(ctx)
}

type recoveryCodesPayload struct {
	Codes []string `json:"codes"`
}

// SaveRecoveryCodes persists the recovery codes once the user downloaded them.
func (h *FrontendHandler) SaveRecoveryCodes(ctx *gin.Context) {
	h.saveCanonicalRecoveryEnrollment(ctx)
}

// PostRegisterRecoveryCodes handles the continue action after recovery codes are saved.
func (h *FrontendHandler) PostRegisterRecoveryCodes(ctx *gin.Context) {
	h.completeCanonicalRecoveryEnrollment(ctx)
}

// PostGenerateRecoveryCodes handles generating new recovery codes.
func (h *FrontendHandler) PostGenerateRecoveryCodes(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_generate_recovery_codes")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.authorizeCanonicalSelfServiceCaller(ctx, nil) {
		return
	}

	_, _, userData, _, err := h.canonicalSelfServiceBackend(ctx)
	if err != nil {
		h.renderErrorModal(ctx, "Failed to fetch user data")

		return
	}

	if !userData.HaveTOTP && !userData.HaveWebAuthn {
		h.renderErrorModal(ctx, "At least one MFA method (TOTP or WebAuthn) must be active to generate recovery codes")

		return
	}

	generator := h.canonicalSelfServiceRecoveryGenerator
	if generator == nil {
		generator = h.generateCanonicalSelfServiceRecoveryCodes
	}

	codes, err := generator(ctx, userData)
	if err != nil {
		sp.RecordError(err)
		h.renderErrorModalWithErr(ctx, "Failed to generate recovery codes", err)

		return
	}

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "recovery", "success").Inc()

	if userData.AuthState != nil {
		userData.AuthState.PurgeCacheFor(userData.Username)
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

	if !h.authorizeCanonicalSelfServiceCaller(ctx, nil) {
		return
	}

	_, _, userData, _, err := h.canonicalSelfServiceBackend(ctx)
	if err != nil {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	deleter := h.canonicalSelfServiceTOTPDeleter
	if deleter == nil {
		deleter = h.deleteCanonicalSelfServiceTOTP
	}

	if err = deleter(ctx, userData); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to delete TOTP secret", err)

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "success").Inc()

	if userData.AuthState != nil {
		userData.AuthState.PurgeCacheFor(userData.Username)
	}

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// deleteWebAuthnCredentials removes every stored WebAuthn credential from the backend.
func (h *FrontendHandler) deleteCanonicalWebAuthnCredentials(userData *UserBackendData) error {
	if userData.WebAuthnUser == nil || len(userData.WebAuthnUser.Credentials) == 0 {
		return nil
	}

	for _, cred := range userData.WebAuthnUser.Credentials {
		credential := cred

		if err := h.deleteCanonicalWebAuthnCredential(userData.AuthState, &credential); err != nil {
			return err
		}
	}

	return nil
}

func (h *FrontendHandler) deleteCanonicalWebAuthnCredential(
	state *core.AuthState,
	credential *mfa.PersistentCredential,
) error {
	if h.canonicalWebAuthnCredentialDelete != nil {
		return h.canonicalWebAuthnCredentialDelete(state, credential)
	}

	if state == nil {
		return errors.ErrUnknownDatabaseBackend
	}

	return state.DeleteWebAuthnCredentialFromSelectedBackend(credential)
}

func (h *FrontendHandler) updateCanonicalWebAuthnCredential(
	state *core.AuthState,
	oldCredential *mfa.PersistentCredential,
	newCredential *mfa.PersistentCredential,
) error {
	if h.canonicalWebAuthnCredentialUpdate != nil {
		return h.canonicalWebAuthnCredentialUpdate(state, oldCredential, newCredential)
	}

	if state == nil {
		return errors.ErrUnknownDatabaseBackend
	}

	return state.UpdateWebAuthnCredentialInSelectedBackend(oldCredential, newCredential)
}

// DeleteWebAuthn removes WebAuthn credentials for the user.
func (h *FrontendHandler) DeleteWebAuthn(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_webauthn")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	if !h.authorizeCanonicalSelfServiceCaller(ctx, nil) {
		return
	}

	_, identity, userData, _, err := h.canonicalSelfServiceBackend(ctx)
	if err != nil || userData == nil || userData.AuthState == nil {
		if err != nil {
			sp.RecordError(err)
		}

		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModal(ctx, "Failed to load user data")

		return
	}

	if err := h.deleteCanonicalWebAuthnCredentials(userData); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to delete WebAuthn credential", err)

		return
	}

	// First, clear the Redis cache
	key := h.deps.Cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + identity.Reference
	if err := h.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), key).Err(); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModalWithErr(ctx, "Failed to delete WebAuthn from Redis", err)

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "success").Inc()

	userData.AuthState.PurgeCacheFor(identity.Account)

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// RegisterWebAuthn renders the WebAuthn registration page.
func (h *FrontendHandler) RegisterWebAuthn(ctx *gin.Context) {
	h.renderCanonicalWebAuthnEnrollment(ctx)
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

	_, _, userData, _, err := h.canonicalSelfServiceBackend(ctx)
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

	if !h.authorizeCanonicalSelfServiceCaller(ctx, nil) {
		return
	}

	decodedID, ok := h.webAuthnDeviceID(ctx)
	if !ok {
		return
	}

	_, _, userData, _, err := h.canonicalSelfServiceBackend(ctx)
	if err != nil || userData == nil || userData.AuthState == nil || userData.WebAuthnUser == nil {
		h.renderErrorModal(ctx, notLoggedInMessage)

		return
	}

	targetIndex := findWebAuthnCredentialIndex(userData.WebAuthnUser, decodedID)
	if targetIndex == -1 {
		h.renderErrorModal(ctx, "Credential not found")

		return
	}

	targetCred := userData.WebAuthnUser.Credentials[targetIndex]
	if err := h.deleteCanonicalWebAuthnCredential(userData.AuthState, &targetCred); err != nil {
		sp.RecordError(err)
		h.renderErrorModalWithErr(ctx, "Failed to delete credential", err)

		return
	}

	if userData.UsesRemoteWebAuthnAuthority() {
		h.finishRemoteWebAuthnAuthorityChange(ctx, userData)
		redirectWebAuthnDevices(ctx)

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

	decodedID, name, ok := h.webAuthnDeviceNameUpdate(ctx)
	if !ok {
		return
	}

	mutation := &mfaSelfServiceStepUpMutation{
		webAuthnCredentialID: ctx.Param("id"),
		webAuthnDeviceName:   name,
	}
	if !h.authorizeCanonicalSelfServiceCaller(ctx, mutation) {
		return
	}

	_, _, userData, _, err := h.canonicalSelfServiceBackend(ctx)
	if err != nil {
		sp.RecordError(err)
		h.renderWebAuthnDeviceNameUpdateFailure(ctx, &webAuthnDeviceNameUpdateFailure{
			err: err, message: notLoggedInMessage,
		})

		return
	}

	if failure := h.applyWebAuthnDeviceNameUpdate(ctx, decodedID, name, userData); failure != nil {
		if failure.err != nil {
			sp.RecordError(failure.err)
		}

		h.renderWebAuthnDeviceNameUpdateFailure(ctx, failure)

		return
	}

	redirectWebAuthnDevices(ctx)
}

// webAuthnDeviceNameUpdateFailure carries a public message and optional internal cause.
type webAuthnDeviceNameUpdateFailure struct {
	err     error
	message string
}

func (h *FrontendHandler) applyWebAuthnDeviceNameUpdate(
	ctx *gin.Context,
	decodedID []byte,
	name string,
	userData *UserBackendData,
) *webAuthnDeviceNameUpdateFailure {
	if userData == nil {
		return &webAuthnDeviceNameUpdateFailure{message: notLoggedInMessage}
	}

	if userData.WebAuthnUser == nil || userData.AuthState == nil {
		return &webAuthnDeviceNameUpdateFailure{message: "User not found"}
	}

	targetIndex := findWebAuthnCredentialIndex(userData.WebAuthnUser, decodedID)
	if targetIndex == -1 {
		return &webAuthnDeviceNameUpdateFailure{message: "Credential not found"}
	}

	oldCredential := userData.WebAuthnUser.Credentials[targetIndex]
	newCredential := oldCredential
	newCredential.Name = name

	if err := h.updateCanonicalWebAuthnCredential(userData.AuthState, &oldCredential, &newCredential); err != nil {
		return &webAuthnDeviceNameUpdateFailure{err: err, message: "Failed to update credential"}
	}

	if userData.UsesRemoteWebAuthnAuthority() {
		h.finishRemoteWebAuthnAuthorityChange(ctx, userData)

		return nil
	}

	h.finishLocalWebAuthnDeviceNameUpdate(ctx, userData, targetIndex, name)

	return nil
}

// renderWebAuthnDeviceNameUpdateFailure renders an interactive rename failure.
func (h *FrontendHandler) renderWebAuthnDeviceNameUpdateFailure(
	ctx *gin.Context,
	failure *webAuthnDeviceNameUpdateFailure,
) {
	if failure == nil {
		return
	}

	if failure.err != nil {
		h.renderErrorModalWithErr(ctx, failure.message, failure.err)

		return
	}

	h.renderErrorModal(ctx, failure.message)
}

// renderPendingWebAuthnDeviceNameError renders post-MFA continuation failures for browser and JSON transports.
func (h *FrontendHandler) renderPendingWebAuthnDeviceNameError(ctx *gin.Context, message string, err error) {
	if strings.Contains(ctx.GetHeader("Content-Type"), "application/json") {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			frontChannelLogoutTaskStatusError: frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, message),
		})

		return
	}

	h.renderWebAuthnDeviceNameUpdateFailure(ctx, &webAuthnDeviceNameUpdateFailure{err: err, message: message})
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

	if len([]rune(name)) > webAuthnDeviceNameMaxRunes {
		h.renderErrorModal(ctx, "Invalid device name")

		return nil, "", false
	}

	return decodedID, name, true
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
}

// finishRemoteWebAuthnAuthorityChange invalidates local cache after an authority-owned mutation.
func (h *FrontendHandler) finishRemoteWebAuthnAuthorityChange(ctx *gin.Context, userData *UserBackendData) {
	_ = backend.DeleteWebAuthnFromRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, userData.UniqueUserID)
	userData.AuthState.PurgeCacheFor(userData.Username)
}

// redirectWebAuthnDevices returns browser and HTMX callers to the localized device list.
func redirectWebAuthnDevices(ctx *gin.Context) {
	target := localizedMFARootPath(ctx, definitions.MFARoot+"/webauthn/devices")
	if ctx.GetHeader("HX-Request") != "" {
		ctx.Header("HX-Redirect", target)
		ctx.Status(http.StatusOK)

		return
	}

	ctx.Redirect(http.StatusSeeOther, target)
}
