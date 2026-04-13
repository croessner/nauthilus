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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	flowdomain "github.com/croessner/nauthilus/server/idp/flow"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/middleware/limit"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	"github.com/croessner/nauthilus/server/middleware/securityheaders"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

// SAMLHandler handles SAML 2.0 protocol requests.
type SAMLHandler struct {
	deps           *deps.Deps
	idp            *idp.NauthilusIdP
	tracer         monittrace.Tracer
	sloRateLimiter *limit.IPRateLimiter
}

type samlLogger struct {
	logger *slog.Logger
}

type sloMessageType string

const (
	sloMessageTypeRequest  sloMessageType = "logout_request"
	sloMessageTypeResponse sloMessageType = "logout_response"

	defaultSLORateLimitPerSecond = 10.0
	defaultSLORateLimitBurst     = 20
	sloMaxInboundMessageBytes    = 512 * 1024
	sloMaxInboundBodyBytes       = 1024 * 1024
)

var (
	errSLOMethodUnsupported = errors.New("unsupported slo method")
	errSLOMissingPayload    = errors.New("missing SAMLRequest/SAMLResponse payload")
	errSLOAmbiguousPayload  = errors.New("SAMLRequest and SAMLResponse must not be present together")
	errSLOPayloadTooLarge   = errors.New("SAML payload exceeds maximum size")
)

type sloInboundMessage struct {
	MessageType sloMessageType
	Binding     slodomain.SLOBinding
	Payload     string
	RelayState  string
}

func (l *samlLogger) Printf(format string, v ...any) {
	l.logger.Info(fmt.Sprintf(format, v...))
}

func (l *samlLogger) Print(v ...any) {
	l.logger.Info(fmt.Sprint(v...))
}

func (l *samlLogger) Println(v ...any) {
	l.logger.Info(fmt.Sprintln(v...))
}

func (l *samlLogger) Fatal(v ...any) {
	l.logger.Error(fmt.Sprint(v...))

	os.Exit(1)
}

func (l *samlLogger) Fatalf(format string, v ...any) {
	l.logger.Error(fmt.Sprintf(format, v...))

	os.Exit(1)
}

func (l *samlLogger) Fatalln(v ...any) {
	l.logger.Error(fmt.Sprintln(v...))

	os.Exit(1)
}

func (l *samlLogger) Panic(v ...any) {
	s := fmt.Sprint(v...)

	l.logger.Error(s)

	panic(s)
}

func (l *samlLogger) Panicf(format string, v ...any) {
	s := fmt.Sprintf(format, v...)

	l.logger.Error(s)

	panic(s)
}

func (l *samlLogger) Panicln(v ...any) {
	s := fmt.Sprintln(v...)

	l.logger.Error(s)

	panic(s)
}

// NewSAMLHandler creates a new SAMLHandler.
func NewSAMLHandler(d *deps.Deps, idp *idp.NauthilusIdP) *SAMLHandler {
	return &SAMLHandler{
		deps:           d,
		idp:            idp,
		tracer:         monittrace.New("nauthilus/idp/saml"),
		sloRateLimiter: newSLORateLimiter(d),
	}
}

func newSLORateLimiter(d *deps.Deps) *limit.IPRateLimiter {
	ratePerSecond := defaultSLORateLimitPerSecond
	burst := defaultSLORateLimitBurst

	if d != nil && d.Cfg != nil {
		serverCfg := d.Cfg.GetServer()
		if serverCfg != nil {
			configuredRate := serverCfg.GetRateLimitPerSecond()
			if configuredRate > 0 && configuredRate < ratePerSecond {
				ratePerSecond = configuredRate
			}

			configuredBurst := serverCfg.GetRateLimitBurst()
			if configuredBurst > 0 && configuredBurst < burst {
				burst = configuredBurst
			}
		}
	}

	return limit.NewIPRateLimiter(limit.Rate(ratePerSecond), burst)
}

func (h *SAMLHandler) allowSLORequest(clientIP string) bool {
	if h == nil || h.sloRateLimiter == nil {
		return true
	}

	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		clientIP = "unknown"
	}

	return h.sloRateLimiter.GetLimiter(clientIP).Allow()
}

func (h *SAMLHandler) sloEnabled() bool {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return true
	}

	return h.deps.Cfg.GetIdP().SAML2.GetSLOEnabled()
}

func sloBindingFromHTTPMethod(method string) slodomain.SLOBinding {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet:
		return slodomain.SLOBindingRedirect
	case http.MethodPost:
		return slodomain.SLOBindingPost
	default:
		return slodomain.SLOBinding("")
	}
}

func isSLOPayloadTooLargeError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, errSLOPayloadTooLarge) {
		return true
	}

	var maxBytesError *http.MaxBytesError

	return errors.As(err, &maxBytesError)
}

func (h *SAMLHandler) sloSessionRegistry() *slodomain.SessionRegistry {
	if h == nil || h.deps == nil || h.deps.Redis == nil {
		return nil
	}

	redisPrefix := h.deps.Cfg.GetServer().GetRedis().GetPrefix()

	return slodomain.NewSessionRegistry(h.deps.Redis.GetWriteHandle(), redisPrefix+"idp:saml:slo")
}

func (h *SAMLHandler) registerSLOParticipantSession(ctx context.Context, account, spEntityID string, session *saml.Session) error {
	if account == "" || spEntityID == "" || session == nil {
		return nil
	}

	registry := h.sloSessionRegistry()
	if registry == nil {
		return nil
	}

	ttl := time.Until(session.ExpireTime)
	if ttl <= 0 {
		ttl = h.deps.Cfg.GetIdP().SAML2.GetDefaultExpireTime()
	}

	return registry.UpsertParticipant(ctx, &slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   spEntityID,
		NameID:       session.NameID,
		SessionIndex: session.Index,
		AuthnInstant: session.CreateTime,
	}, ttl)
}

func (h *SAMLHandler) deleteSLOParticipantSessionsByAccount(ctx context.Context, account string) error {
	if account == "" {
		return nil
	}

	registry := h.sloSessionRegistry()
	if registry == nil {
		return nil
	}

	return registry.DeleteAccount(ctx, account)
}

// GetServiceProvider returns the Service Provider metadata for the given entity ID.
func (h *SAMLHandler) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	sp, ok := h.idp.FindSAMLServiceProvider(serviceProviderID)
	if !ok {
		return nil, os.ErrNotExist
	}

	ssoDescriptor := saml.SPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			},
		},
		AssertionConsumerServices: []saml.IndexedEndpoint{
			{
				Binding:  saml.HTTPPostBinding,
				Location: sp.ACSURL,
				Index:    1,
			},
		},
	}

	if strings.TrimSpace(sp.SLOURL) != "" {
		ssoDescriptor.SingleLogoutServices = []saml.Endpoint{
			{
				Binding:          saml.HTTPRedirectBinding,
				Location:         sp.SLOURL,
				ResponseLocation: sp.SLOURL,
			},
			{
				Binding:          saml.HTTPPostBinding,
				Location:         sp.SLOURL,
				ResponseLocation: sp.SLOURL,
			},
		}
	}

	if sp.AreAuthnRequestsSigned() {
		authnRequestsSigned := true
		ssoDescriptor.AuthnRequestsSigned = &authnRequestsSigned
	}

	// If SP certificate is configured, add KeyDescriptor for signature
	// verification and assertion encryption.
	keyDescriptors, err := buildSPKeyDescriptors(sp)
	if err != nil {
		return nil, err
	}

	if len(keyDescriptors) > 0 {
		ssoDescriptor.RoleDescriptor.KeyDescriptors = keyDescriptors
	}

	return &saml.EntityDescriptor{
		EntityID:         sp.EntityID,
		SPSSODescriptors: []saml.SPSSODescriptor{ssoDescriptor},
	}, nil
}

// buildSPKeyDescriptors parses the SP certificate and returns KeyDescriptors
// for the EntityDescriptor. Returns nil if no certificate is configured.
func buildSPKeyDescriptors(sp *config.SAML2ServiceProvider) ([]saml.KeyDescriptor, error) {
	certStr, err := sp.GetCert()
	if err != nil {
		return nil, fmt.Errorf("failed to read SP certificate: %w", err)
	}

	if certStr == "" {
		return nil, nil
	}

	block, _ := pem.Decode([]byte(certStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse SP certificate PEM for entity %s", sp.EntityID)
	}

	certBase64 := base64.StdEncoding.EncodeToString(block.Bytes)

	return []saml.KeyDescriptor{
		{
			// Use="" means the key can be used for both signing and encryption.
			KeyInfo: saml.KeyInfo{
				X509Data: saml.X509Data{
					X509Certificates: []saml.X509Certificate{
						{Data: certBase64},
					},
				},
			},
		},
	}, nil
}

func (h *SAMLHandler) getSAMLIdP() (*saml.IdentityProvider, error) {
	samlCfg := h.deps.Cfg.GetIdP().SAML2
	certStr, err := samlCfg.GetCert()
	if err != nil {
		return nil, err
	}
	keyStr, err := samlCfg.GetKey()
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(certStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	block, _ = pem.Decode([]byte(keyStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	var key any
	if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
	}

	issuer := h.deps.Cfg.GetIdP().OIDC.Issuer

	entityID := samlCfg.EntityID
	if entityID == "" {
		entityID = issuer + "/saml/metadata"
	}

	metadataURL, _ := url.Parse(entityID)

	ssoURLStr := issuer + "/saml/sso"
	sloURLStr := issuer + "/saml/slo"

	if samlCfg.EntityID != "" {
		// If EntityID is a full URL, try to use it as base for SSO URL
		if u, err := url.Parse(samlCfg.EntityID); err == nil && u.Scheme != "" && u.Host != "" {
			u.Path = "/saml/sso"
			u.RawQuery = ""
			u.Fragment = ""
			ssoURLStr = u.String()

			u.Path = "/saml/slo"
			sloURLStr = u.String()
		}
	}

	ssoURL, _ := url.Parse(ssoURLStr)
	sloURL, _ := url.Parse(sloURLStr)

	return &saml.IdentityProvider{
		Key:                     key.(crypto.PrivateKey),
		Certificate:             cert,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		LogoutURL:               *sloURL,
		ServiceProviderProvider: h,
		SignatureMethod:         samlCfg.GetSignatureMethod(),
		Logger:                  &samlLogger{logger: h.deps.Logger},
	}, nil
}

// Register adds SAML routes to the router.
func (h *SAMLHandler) Register(router gin.IRouter) {
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIdP)
		ctx.Next()
	}, mdlua.LuaContextMiddleware())

	var frontendSecret []byte
	h.deps.Cfg.GetServer().GetFrontend().GetEncryptionSecret().WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		frontendSecret = bytes.Clone(value)
	})
	secureMW := cookie.Middleware(frontendSecret, h.deps.Cfg, h.deps.Env)
	securityMW := securityheaders.New(securityheaders.MiddlewareConfig{Config: h.deps.Cfg}).Handler()

	router.GET("/saml/metadata", securityMW, h.Metadata)
	router.GET("/saml/sso", securityMW, secureMW, h.SSO)
	router.GET("/saml/slo", securityMW, secureMW, h.SLO)
	router.POST("/saml/slo", securityMW, secureMW, h.SLO)
}

// Metadata returns the SAML IdP metadata.
func (h *SAMLHandler) Metadata(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "saml.metadata")
	defer sp.End()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML Metadata request",
	)

	idpObj, err := h.getSAMLIdP()
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to initialize SAML IdP: %v", err)

		return
	}

	metadata := idpObj.Metadata()

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to marshal SAML metadata: %v", err)

		return
	}

	ctx.Data(http.StatusOK, "application/xml", buf)
}

// SSO handles the SAML Single Sign-On request (Redirect Binding).
func (h *SAMLHandler) SSO(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "saml.sso")
	defer sp.End()

	h.logIncomingSAMLFlowRequest(ctx, "sso", "")
	defer h.logCompletedSAMLFlowRequest(ctx, "sso", "")

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SSO request",
	)

	idpObj, err := h.getSAMLIdP()
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to initialize SAML IdP: %v", err)

		return
	}

	req, err := saml.NewIdpAuthnRequest(idpObj, ctx.Request)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Failed to parse SAML request: %v", err)

		return
	}

	var acsURL string
	if req.ACSEndpoint != nil {
		acsURL = req.ACSEndpoint.Location
	}

	var issuer string
	if req.Request.Issuer != nil {
		issuer = req.Request.Issuer.Value
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SSO request details",
		"acs_url", util.WithNotAvailable(acsURL),
		"issuer", util.WithNotAvailable(issuer),
		"request_id", req.Request.ID,
	)

	if err := req.Validate(); err != nil {
		ctx.String(http.StatusBadRequest, "Failed to validate SAML request: %v", err)

		return
	}

	mgr := cookie.GetManager(ctx)
	account := ""

	if mgr != nil {
		account = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	if account == "" {
		// User not logged in - store SAML flow state in secure cookie and redirect to login.
		// This prevents open redirect vulnerabilities by not passing return_to in URL.
		redirectTarget := "/login"

		if mgr != nil {
			controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

			decision, err := controller.Start(ctx.Request.Context(), &flowdomain.State{
				FlowID:       ksuid.New().String(),
				FlowType:     flowdomain.FlowTypeSAML,
				Protocol:     flowdomain.FlowProtocolSAML,
				CurrentStep:  flowdomain.FlowStepStart,
				ReturnTarget: "/login",
				Metadata: map[string]string{
					flowdomain.FlowMetadataSAMLEntityID: issuer,
					flowdomain.FlowMetadataOriginalURL:  ctx.Request.URL.String(),
					flowdomain.FlowMetadataResumeTarget: ctx.Request.URL.RequestURI(),
				},
			}, time.Now())
			if err != nil {
				ctx.String(http.StatusInternalServerError, "Failed to initialize flow session")

				return
			}

			redirectTarget = decision.RedirectURI

			samlFlowCtx := newSAMLFlowContext(mgr)
			samlFlowCtx.StoreRequest(issuer, ctx.Request.URL.String())

			// Explicitly save cookie before redirect to ensure it's written to the response
			if err := samlFlowCtx.Save(ctx); err != nil {
				ctx.String(http.StatusInternalServerError, "Failed to save session")

				return
			}

			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "SAML flow state stored in cookie - redirecting to login",
				"issuer", util.WithNotAvailable(issuer),
			)
		}

		ctx.Redirect(http.StatusFound, redirectTarget)

		return
	}

	// User is logged in
	username := account

	// We need user details for the assertion
	issuerValue := ""
	if req.Request.Issuer != nil {
		issuerValue = req.Request.Issuer.Value
	}

	user, err := h.idp.GetUserByUsername(ctx, username, "", issuerValue)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to load user details: %v", err)

		return
	}

	// Cleanup IP address (remove port) for SAML assertion compatibility
	if ip, _, err := net.SplitHostPort(req.HTTPRequest.RemoteAddr); err == nil {
		req.HTTPRequest.RemoteAddr = ip
	}

	// Create SAML session
	samlSessionID, _ := util.GenerateRandomString(32)
	samlSessionIndex, _ := util.GenerateRandomString(32)

	samlSession := &saml.Session{
		ID:           samlSessionID,
		CreateTime:   time.Now().UTC(),
		ExpireTime:   time.Now().Add(h.deps.Cfg.GetIdP().SAML2.GetDefaultExpireTime()).UTC(),
		Index:        samlSessionIndex,
		UserName:     username,
		NameID:       username,
		NameIDFormat: h.deps.Cfg.GetIdP().SAML2.GetNameIDFormat(),
	}

	// Add attributes (filtered by allowed_attributes if configured)
	samlSP, _ := h.idp.FindSAMLServiceProvider(issuerValue)
	allowedAttrs := samlSP.GetAllowedAttributes()

	for k, v := range user.Attributes {
		if len(v) == 0 {
			continue
		}

		if len(allowedAttrs) > 0 && !slices.Contains(allowedAttrs, k) {
			continue
		}

		samlSession.CustomAttributes = append(samlSession.CustomAttributes, saml.Attribute{
			Name: k,
			Values: []saml.AttributeValue{
				{
					Type:  "xs:string",
					Value: fmt.Sprintf("%v", v[0]),
				},
			},
		})
	}

	req.Now = time.Now().UTC()

	assertionMaker := saml.DefaultAssertionMaker{}
	if err := assertionMaker.MakeAssertion(req, samlSession); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to make SAML assertion: %v", err)

		return
	}

	if err = h.registerSLOParticipantSession(ctx.Request.Context(), username, issuerValue, samlSession); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to persist SAML SLO session: %v", err)

		return
	}

	// Complete the flow: advance to callback, delete Redis state, and clean up cookie keys
	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepCallback)
	completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	form, err := req.PostBinding()
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to create SAML response form: %v", err)

		return
	}

	data := gin.H{
		"LanguageTag":         "en",
		"LanguageCurrentName": "English",
		"LanguagePassive":     []map[string]string{},
		"CSPNonce":            securityheaders.NonceFromContext(ctx),
		"ConfirmTitle":        frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Confirmation"),
		"ConfirmYes":          frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Yes"),
		"ConfirmNo":           frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel"),
		"IdPClientName":       "",
	}
	if h.deps != nil && h.deps.LangManager != nil {
		data = BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
	} else {
		setLegalLinksData(ctx, h.deps.Cfg, data)
	}

	data["DevMode"] = h.deps.Env.GetDevMode()
	data["HXRequest"] = ctx.GetHeader("HX-Request") != ""
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Continue")
	data["SAMLPostTitle"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Signing you in")
	data["SAMLPostMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You are being redirected to the application.")
	data["SAMLPostHint"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "If this does not happen automatically, click Continue.")
	data["Continue"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Continue")
	data["AutoSubmitSAMLForm"] = true
	data["SAMLPostURL"] = form.URL
	data["SAMLResponse"] = form.SAMLResponse
	data["RelayState"] = form.RelayState

	ctx.HTML(http.StatusOK, "idp_saml_post.html", data)
}

// SLO handles the SAML Single Logout request.
func (h *SAMLHandler) SLO(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "saml.slo")
	defer sp.End()

	h.logIncomingSAMLFlowRequest(ctx, "slo", "")
	defer h.logCompletedSAMLFlowRequest(ctx, "slo", "")

	startTime := time.Now().UTC()
	binding := sloBindingFromHTTPMethod(ctx.Request.Method)
	messageType := sloMessageType("")
	defer func() {
		observeSLORequest(binding, messageType, sloRequestOutcomeFromHTTPStatus(ctx.Writer.Status()), time.Since(startTime))
	}()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SLO request",
	)

	if !h.sloEnabled() {
		h.auditSLOEvent(
			ctx.Request.Context(),
			"request_rejected",
			"",
			"",
			"",
			"binding", binding,
			"reason", "slo_disabled",
		)
		ctx.String(http.StatusNotFound, "SAML SLO endpoint is disabled")

		return
	}

	if !h.allowSLORequest(ctx.ClientIP()) {
		recordSLOAbuseRejection(sloAbuseReasonRateLimit, binding)
		recordSLOValidationError(sloValidationStageAbuseGuard, messageType, binding)
		h.auditSLOEvent(
			ctx.Request.Context(),
			"request_blocked",
			"",
			"",
			"",
			"binding", binding,
			"reason", sloAbuseReasonRateLimit,
			"client_ip", util.WithNotAvailable(strings.TrimSpace(ctx.ClientIP())),
		)
		ctx.Header("Retry-After", "1")
		ctx.String(http.StatusTooManyRequests, "SAML SLO rate limit exceeded")

		return
	}

	if ctx.Request.Method == http.MethodPost && ctx.Request.Body != nil {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, sloMaxInboundBodyBytes)
	}

	message, err := routeSLOInboundMessage(ctx.Request)
	if err != nil {
		recordSLOValidationError(sloValidationStagePayload, messageType, binding)
		if isSLOPayloadTooLargeError(err) {
			recordSLOAbuseRejection(sloAbuseReasonPayloadTooBig, binding)
		}
		h.auditSLOEvent(
			ctx.Request.Context(),
			"validation_failed",
			"",
			"",
			"",
			"binding", binding,
			"stage", sloValidationStagePayload,
			"error", err.Error(),
		)
		ctx.String(http.StatusBadRequest, "Invalid SAML SLO payload: %v", err)

		return
	}

	binding = message.Binding
	messageType = message.MessageType

	switch message.MessageType {
	case sloMessageTypeRequest:
		h.handleLogoutRequest(ctx, message)
	case sloMessageTypeResponse:
		h.handleLogoutResponse(ctx, message)
	default:
		recordSLOValidationError(sloValidationStagePayload, messageType, binding)
		h.auditSLOEvent(
			ctx.Request.Context(),
			"validation_failed",
			"",
			"",
			"",
			"binding", binding,
			"stage", sloValidationStagePayload,
			"error", "unsupported message type",
		)
		ctx.String(http.StatusBadRequest, "Invalid SAML SLO payload: unsupported message type")
	}
}

func routeSLOInboundMessage(req *http.Request) (*sloInboundMessage, error) {
	if req == nil {
		return nil, errSLOMethodUnsupported
	}

	switch req.Method {
	case http.MethodGet:
		return parseSLOMessageFromValues(req.URL.Query(), slodomain.SLOBindingRedirect)
	case http.MethodPost:
		if err := req.ParseForm(); err != nil {
			return nil, fmt.Errorf("parse form payload: %w", err)
		}

		return parseSLOMessageFromValues(req.PostForm, slodomain.SLOBindingPost)
	default:
		return nil, fmt.Errorf("%w: %s", errSLOMethodUnsupported, req.Method)
	}
}

func parseSLOMessageFromValues(values url.Values, binding slodomain.SLOBinding) (*sloInboundMessage, error) {
	request, err := validateSingleSLOParam(values, "SAMLRequest")
	if err != nil {
		return nil, err
	}

	response, err := validateSingleSLOParam(values, "SAMLResponse")
	if err != nil {
		return nil, err
	}

	relayState, err := validateSingleSLOParam(values, "RelayState")
	if err != nil {
		return nil, err
	}

	switch {
	case request != "" && response != "":
		return nil, errSLOAmbiguousPayload
	case request == "" && response == "":
		return nil, errSLOMissingPayload
	case request != "":
		return &sloInboundMessage{
			MessageType: sloMessageTypeRequest,
			Binding:     binding,
			Payload:     request,
			RelayState:  relayState,
		}, nil
	default:
		return &sloInboundMessage{
			MessageType: sloMessageTypeResponse,
			Binding:     binding,
			Payload:     response,
			RelayState:  relayState,
		}, nil
	}
}

func validateSingleSLOParam(values url.Values, key string) (string, error) {
	entries, exists := values[key]
	if !exists || len(entries) == 0 {
		return "", nil
	}

	if len(entries) > 1 {
		return "", fmt.Errorf("parameter %s is duplicated", key)
	}

	if (key == "SAMLRequest" || key == "SAMLResponse") && len(entries[0]) > sloMaxInboundMessageBytes {
		return "", fmt.Errorf("%w: parameter %s exceeds %d bytes", errSLOPayloadTooLarge, key, sloMaxInboundMessageBytes)
	}

	value := strings.TrimSpace(entries[0])
	if value == "" {
		return "", fmt.Errorf("parameter %s is empty", key)
	}

	return value, nil
}

func samlIssuerValue(issuer *saml.Issuer) string {
	if issuer == nil {
		return ""
	}

	return strings.TrimSpace(issuer.Value)
}

func (h *SAMLHandler) handleLogoutRequest(ctx *gin.Context, message *sloInboundMessage) {
	binding := slodomain.SLOBinding("")
	if message != nil {
		binding = message.Binding
	}

	logoutRequest, err := h.validateInboundLogoutRequestSignature(ctx.Request, message)
	if err != nil {
		recordSLOValidationError(sloValidationStageSignature, sloMessageTypeRequest, binding)
		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_request_rejected",
			"",
			"",
			"",
			"binding", binding,
			"stage", sloValidationStageSignature,
			"error", err.Error(),
		)
		ctx.String(http.StatusBadRequest, "Invalid SAML LogoutRequest signature: %v", err)

		return
	}

	requestID := strings.TrimSpace(logoutRequest.ID)
	issuer := ""
	if logoutRequest.Issuer != nil {
		issuer = strings.TrimSpace(logoutRequest.Issuer.Value)
	}

	if err = h.validateInboundLogoutRequestProtocol(ctx.Request.Context(), logoutRequest); err != nil {
		recordSLOValidationError(sloValidationStageProtocol, sloMessageTypeRequest, binding)
		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_request_rejected",
			"",
			requestID,
			issuer,
			"binding", binding,
			"stage", sloValidationStageProtocol,
			"error", err.Error(),
		)
		ctx.String(http.StatusBadRequest, "Invalid SAML LogoutRequest protocol: %v", err)

		return
	}

	sloTransaction, err := h.newValidatedSLOTransaction(logoutRequest, message.Binding)
	if err != nil {
		recordSLOValidationError(sloValidationStageTransaction, sloMessageTypeRequest, binding)
		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_request_rejected",
			"",
			requestID,
			issuer,
			"binding", binding,
			"stage", sloValidationStageTransaction,
			"error", err.Error(),
		)
		ctx.String(http.StatusBadRequest, "Invalid SAML LogoutRequest transaction: %v", err)

		return
	}

	account := ""
	if logoutRequest.NameID != nil {
		account = strings.TrimSpace(logoutRequest.NameID.Value)
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SLO routed LogoutRequest",
		"binding", message.Binding,
		"relay_state", util.WithNotAvailable(message.RelayState),
		"issuer", util.WithNotAvailable(issuer),
		"request_id", util.WithNotAvailable(logoutRequest.ID),
		"transaction_id", sloTransaction.TransactionID,
	)

	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_request_validated",
		sloTransaction.TransactionID,
		requestID,
		issuer,
		"binding", binding,
		"relay_state", util.WithNotAvailable(message.RelayState),
	)

	cleanupResult := h.performLocalSLOCleanupInternal(ctx, account, sloTransaction, false)
	terminalStatus := sloTerminalStatusFromCleanup(cleanupResult)
	recordSLOTerminalStatus(slodomain.SLODirectionSPInitiated, terminalStatus)

	auditKeyvals := []any{
		"binding", binding,
		"status", terminalStatus,
		"account", util.WithNotAvailable(account),
	}

	if cleanupResult.TransitionErr != nil {
		auditKeyvals = append(auditKeyvals, "cleanup_transition_error", cleanupResult.TransitionErr.Error())
	}

	if cleanupResult.ParticipantCleanupErr != nil {
		auditKeyvals = append(auditKeyvals, "participant_cleanup_error", cleanupResult.ParticipantCleanupErr.Error())
	}

	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_request_local_cleanup",
		sloTransaction.TransactionID,
		requestID,
		issuer,
		auditKeyvals...,
	)

	if err = h.respondToLogoutRequest(ctx, logoutRequest, message, cleanupResult); err != nil {
		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_response_failed",
			sloTransaction.TransactionID,
			requestID,
			issuer,
			"binding", binding,
			"error", err.Error(),
		)
		ctx.String(http.StatusInternalServerError, "Failed to create SAML LogoutResponse: %v", err)

		return
	}

	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_response_sent",
		sloTransaction.TransactionID,
		requestID,
		issuer,
		"binding", binding,
		"status", terminalStatus,
	)
}

func (h *SAMLHandler) handleLogoutResponse(ctx *gin.Context, message *sloInboundMessage) {
	binding := slodomain.SLOBinding("")
	if message != nil {
		binding = message.Binding
	}

	logoutResponse, err := h.validateInboundLogoutResponseSignature(ctx.Request, message)
	if err != nil {
		recordSLOValidationError(sloValidationStageSignature, sloMessageTypeResponse, binding)
		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_response_rejected",
			"",
			"",
			"",
			"binding", binding,
			"stage", sloValidationStageSignature,
			"error", err.Error(),
		)
		ctx.String(http.StatusBadRequest, "Invalid SAML LogoutResponse signature: %v", err)

		return
	}

	requestID := strings.TrimSpace(logoutResponse.InResponseTo)
	issuer := samlIssuerValue(logoutResponse.Issuer)

	if err = h.validateInboundLogoutResponseProtocol(logoutResponse); err != nil {
		recordSLOValidationError(sloValidationStageProtocol, sloMessageTypeResponse, binding)
		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_response_rejected",
			"",
			requestID,
			issuer,
			"binding", binding,
			"stage", sloValidationStageProtocol,
			"error", err.Error(),
		)
		ctx.String(http.StatusBadRequest, "Invalid SAML LogoutResponse protocol: %v", err)

		return
	}

	aggregation, err := h.applySLOFanoutLogoutResponse(ctx.Request.Context(), logoutResponse, message.RelayState)
	if err != nil {
		recordSLOValidationError(sloValidationStageCorrelation, sloMessageTypeResponse, binding)
		status := http.StatusBadRequest
		if errors.Is(err, errSLOFanoutStateUnavailable) {
			status = http.StatusInternalServerError
		}

		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_response_rejected",
			"",
			requestID,
			issuer,
			"binding", binding,
			"stage", sloValidationStageCorrelation,
			"error", err.Error(),
		)
		ctx.String(status, "Cannot correlate SAML LogoutResponse: %v", err)

		return
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SLO routed LogoutResponse",
		"binding", message.Binding,
		"relay_state", util.WithNotAvailable(message.RelayState),
		"issuer", util.WithNotAvailable(samlIssuerValue(logoutResponse.Issuer)),
		"in_response_to", util.WithNotAvailable(logoutResponse.InResponseTo),
		"transaction_id", util.WithNotAvailable(aggregation.TransactionID),
		"participant", util.WithNotAvailable(aggregation.ParticipantEntity),
		"pending", aggregation.PendingCount,
		"success_count", aggregation.SuccessCount,
		"failure_count", aggregation.FailureCount,
		"status", aggregation.Status,
		"final", aggregation.Final,
	)

	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_response_processed",
		aggregation.TransactionID,
		requestID,
		aggregation.ParticipantEntity,
		"binding", binding,
		"status", aggregation.Status,
		"success_count", aggregation.SuccessCount,
		"failure_count", aggregation.FailureCount,
		"pending", aggregation.PendingCount,
		"final", aggregation.Final,
	)

	ctx.String(http.StatusOK, "SAML LogoutResponse processed")
}

func (h *SAMLHandler) newValidatedSLOTransaction(
	logoutRequest *saml.LogoutRequest,
	binding slodomain.SLOBinding,
) (*slodomain.SLOTransaction, error) {
	if logoutRequest == nil {
		return nil, fmt.Errorf("logout request payload is missing")
	}

	requestID := strings.TrimSpace(logoutRequest.ID)
	if requestID == "" {
		return nil, fmt.Errorf("logout request id is missing")
	}

	now := time.Now().UTC()
	transaction, err := slodomain.NewTransaction(
		ksuid.New().String(),
		requestID,
		slodomain.SLODirectionSPInitiated,
		binding,
		now,
	)
	if err != nil {
		return nil, err
	}

	if logoutRequest.NameID != nil {
		transaction.Account = strings.TrimSpace(logoutRequest.NameID.Value)
	}

	if err = transaction.TransitionTo(slodomain.SLOStatusValidated, now); err != nil {
		return nil, err
	}

	return transaction, nil
}

func (h *SAMLHandler) performLocalSLOCleanup(
	ctx *gin.Context,
	accountHint string,
	transaction *slodomain.SLOTransaction,
) {
	h.performLocalSLOCleanupInternal(ctx, accountHint, transaction, true)
}

type sloLocalCleanupResult struct {
	Account               string
	TransitionErr         error
	ParticipantCleanupErr error
}

func (h *SAMLHandler) performLocalSLOCleanupInternal(
	ctx *gin.Context,
	accountHint string,
	transaction *slodomain.SLOTransaction,
	redirectToLoggedOut bool,
) sloLocalCleanupResult {
	mgr := cookie.GetManager(ctx)
	account := strings.TrimSpace(accountHint)
	result := sloLocalCleanupResult{
		Account: account,
	}

	if account == "" && mgr != nil {
		account = strings.TrimSpace(mgr.GetString(definitions.SessionKeyAccount, ""))
		result.Account = account
	}

	if transaction != nil {
		if transaction.Account == "" {
			transaction.Account = account
		}

		if err := transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC()); err != nil {
			result.TransitionErr = err

			if h != nil && h.deps != nil {
				util.DebugModuleWithCfg(
					ctx.Request.Context(),
					h.deps.Cfg,
					h.deps.Logger,
					definitions.DbgIdp,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, "Failed to transition SLO transaction to local_done",
					"transaction_id", util.WithNotAvailable(transaction.TransactionID),
					"error", err.Error(),
				)
			}
		}
	}

	if mgr != nil {
		var redisClient rediscli.Client
		if h != nil && h.deps != nil {
			redisClient = h.deps.Redis
		}

		abortFlow(ctx.Request.Context(), mgr, redisClient, h.redisPrefix())
		CleanupMFAState(mgr)
		flowdomain.ClearRequireMFAContext(mgr)
	}

	core.SessionCleaner(ctx)

	if err := h.deleteSLOParticipantSessionsByAccount(ctx.Request.Context(), account); err != nil {
		result.ParticipantCleanupErr = err

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to cleanup SAML SLO participant sessions",
			"account", util.WithNotAvailable(account),
			"error", err.Error(),
		)
	}

	core.ClearBrowserCookies(ctx)

	if redirectToLoggedOut {
		ctx.Redirect(http.StatusFound, "/logged_out")
	}

	return result
}

func (h *SAMLHandler) redisPrefix() string {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || h.deps.Cfg.GetServer() == nil {
		return ""
	}

	return h.deps.Cfg.GetServer().GetRedis().GetPrefix()
}
