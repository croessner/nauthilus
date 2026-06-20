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
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/croessner/nauthilus/v3/server/middleware/limit"
	mdlua "github.com/croessner/nauthilus/v3/server/middleware/lua"
	"github.com/croessner/nauthilus/v3/server/middleware/securityheaders"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

// SAMLHandler handles SAML 2.0 protocol requests.
type SAMLHandler struct {
	deps           *deps.Deps
	idp            *idp.NauthilusIDP
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
	samlAttributeTypeString      = "xs:string"
)

var (
	errSLOMethodUnsupported = errors.New("unsupported slo method")
	errSLOMissingPayload    = errors.New("missing SAMLRequest/SAMLResponse payload")
	errSLOAmbiguousPayload  = errors.New("SAMLRequest and SAMLResponse must not be present together")
	errSLOPayloadTooLarge   = errors.New("SAML payload exceeds maximum size")
)

type sloInboundMessage struct {
	MessageType sloMessageType
	Binding     slodomain.Binding
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
func NewSAMLHandler(d *deps.Deps, idp *idp.NauthilusIDP) *SAMLHandler {
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

	return h.deps.Cfg.GetIDP().SAML2.GetSLOEnabled()
}

func sloBindingFromHTTPMethod(method string) slodomain.Binding {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet:
		return slodomain.SLOBindingRedirect
	case http.MethodPost:
		return slodomain.SLOBindingPost
	default:
		return slodomain.Binding("")
	}
}

func isSLOPayloadTooLargeError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, errSLOPayloadTooLarge) {
		return true
	}

	_, ok := errors.AsType[*http.MaxBytesError](err)

	return ok
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
		ttl = h.deps.Cfg.GetIDP().SAML2.GetDefaultExpireTime()
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
		ssoDescriptor.KeyDescriptors = keyDescriptors
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

func (h *SAMLHandler) getSAMLIDP() (*saml.IdentityProvider, error) {
	samlCfg := h.deps.Cfg.GetIDP().SAML2

	certStr, err := samlCfg.GetCert()
	if err != nil {
		return nil, err
	}

	keyStr, err := samlCfg.GetKey()
	if err != nil {
		return nil, err
	}

	cert, err := parseSAMLIDPCertificate(certStr)
	if err != nil {
		return nil, err
	}

	key, err := parseSAMLIDPPrivateKey(keyStr)
	if err != nil {
		return nil, err
	}

	issuer := h.deps.Cfg.GetIDP().OIDC.Issuer
	metadataURL, ssoURL, sloURL := resolveSAMLIDPEndpoints(samlCfg, issuer)

	return &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             metadataURL,
		SSOURL:                  ssoURL,
		LogoutURL:               sloURL,
		ServiceProviderProvider: h,
		SignatureMethod:         samlCfg.GetSignatureMethod(),
		Logger:                  &samlLogger{logger: h.deps.Logger},
	}, nil
}

// parseSAMLIDPCertificate parses the configured SAML IdP certificate.
func parseSAMLIDPCertificate(certStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

// parseSAMLIDPPrivateKey parses the configured SAML IdP signing key.
func parseSAMLIDPPrivateKey(keyStr string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return key, nil
}

// resolveSAMLIDPEndpoints derives metadata, SSO, and SLO URLs from SAML configuration.
func resolveSAMLIDPEndpoints(samlCfg config.SAML2Config, issuer string) (url.URL, url.URL, url.URL) {
	entityID := samlCfg.EntityID
	if entityID == "" {
		entityID = issuer + "/saml/metadata"
	}

	metadataURL, _ := url.Parse(entityID)
	ssoURLStr := issuer + "/saml/sso"
	sloURLStr := issuer + frontendSAMLLogoutPath

	if samlCfg.EntityID != "" {
		// If EntityID is a full URL, try to use it as base for SSO URL.
		if u, err := url.Parse(samlCfg.EntityID); err == nil && u.Scheme != "" && u.Host != "" {
			u.Path = "/saml/sso"
			u.RawQuery = ""
			u.Fragment = ""
			ssoURLStr = u.String()

			u.Path = frontendSAMLLogoutPath
			sloURLStr = u.String()
		}
	}

	ssoURL, _ := url.Parse(ssoURLStr)
	sloURL, _ := url.Parse(sloURLStr)

	return *metadataURL, *ssoURL, *sloURL
}

// Register adds SAML routes to the router.
func (h *SAMLHandler) Register(router gin.IRouter) {
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
		ctx.Next()
	}, mdlua.ContextMiddleware())

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
	router.GET(frontendSAMLLogoutPath, securityMW, secureMW, h.SLO)
	router.POST(frontendSAMLLogoutPath, securityMW, secureMW, h.SLO)
}

// Metadata returns the SAML IDP metadata.
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

	idpObj, err := h.getSAMLIDP()
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to initialize SAML IDP: %v", err)

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

	idpObj, err := h.getSAMLIDP()
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to initialize SAML IDP: %v", err)

		return
	}

	req, err := saml.NewIdpAuthnRequest(idpObj, ctx.Request)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Failed to parse SAML request: %v", err)

		return
	}

	if err := req.Validate(); err != nil {
		ctx.String(http.StatusBadRequest, "Failed to validate SAML request: %v", err)

		return
	}

	issuer := samlAuthnRequestIssuer(req)
	h.logSAMLSSORequestDetails(ctx, req, issuer)

	mgr := cookie.GetManager(ctx)
	account := ""

	if mgr != nil {
		account = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	if account == "" {
		h.redirectUnauthenticatedSAMLSSO(ctx, mgr, issuer)

		return
	}

	h.handleAuthenticatedSAMLSSO(ctx, mgr, req, issuer, account)
}

// handleAuthenticatedSAMLSSO issues the SAML assertion for an already logged-in account.
func (h *SAMLHandler) handleAuthenticatedSAMLSSO(
	ctx *gin.Context,
	mgr cookie.Manager,
	req *saml.IdpAuthnRequest,
	issuer string,
	username string,
) {
	samlSP, ok := h.idp.FindSAMLServiceProvider(issuer)
	if !ok {
		ctx.String(http.StatusBadRequest, "Invalid SAML service provider")

		return
	}

	user, err := h.idp.GetUserByUsernameForSAML(ctx, username, samlSP)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to load user details: %v", err)

		return
	}

	normalizeSAMLRequestRemoteAddr(req)

	samlSession := h.newSAMLAuthnSession(username)
	populateSAMLSessionAttributes(samlSession, user, samlSP)

	req.Now = time.Now().UTC()

	assertionMaker := saml.DefaultAssertionMaker{}
	if err := assertionMaker.MakeAssertion(req, samlSession); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to make SAML assertion: %v", err)

		return
	}

	if err = h.registerSLOParticipantSession(ctx.Request.Context(), username, issuer, samlSession); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to persist SAML SLO session: %v", err)

		return
	}

	h.completeSAMLSSOFlow(ctx, mgr)

	form, err := req.PostBinding()
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to create SAML response form: %v", err)

		return
	}

	h.renderSAMLPostBinding(ctx, form)
}

// samlAuthnRequestIssuer returns the trimmed issuer from a parsed SAML AuthnRequest.
func samlAuthnRequestIssuer(req *saml.IdpAuthnRequest) string {
	if req == nil || req.Request.Issuer == nil {
		return ""
	}

	return strings.TrimSpace(req.Request.Issuer.Value)
}

// samlAuthnRequestACSURL returns the Assertion Consumer Service URL for logging.
func samlAuthnRequestACSURL(req *saml.IdpAuthnRequest) string {
	if req == nil || req.ACSEndpoint == nil {
		return ""
	}

	return req.ACSEndpoint.Location
}

// logSAMLSSORequestDetails records non-secret request routing details.
func (h *SAMLHandler) logSAMLSSORequestDetails(ctx *gin.Context, req *saml.IdpAuthnRequest, issuer string) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SSO request details",
		"acs_url", util.WithNotAvailable(samlAuthnRequestACSURL(req)),
		"issuer", util.WithNotAvailable(issuer),
		"request_id", req.Request.ID,
	)
}

// redirectUnauthenticatedSAMLSSO stores SAML flow state and sends the browser to login.
func (h *SAMLHandler) redirectUnauthenticatedSAMLSSO(ctx *gin.Context, mgr cookie.Manager, issuer string) {
	redirectTarget := frontendLoginPath

	if mgr != nil {
		decision, err := h.startSAMLSSOLoginFlow(ctx, mgr, issuer)
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Failed to initialize flow session")

			return
		}

		redirectTarget = decision.RedirectURI

		if !h.storeSAMLSSORequestContext(ctx, mgr, issuer) {
			return
		}
	}

	ctx.Redirect(http.StatusFound, redirectTarget)
}

// startSAMLSSOLoginFlow creates the cookie-backed flow state for SAML login.
func (h *SAMLHandler) startSAMLSSOLoginFlow(ctx *gin.Context, mgr cookie.Manager, issuer string) (flowdomain.Decision, error) {
	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	return controller.Start(ctx.Request.Context(), &flowdomain.State{
		FlowID:       ksuid.New().String(),
		Type:         flowdomain.FlowTypeSAML,
		Protocol:     flowdomain.FlowProtocolSAML,
		CurrentStep:  flowdomain.FlowStepStart,
		ReturnTarget: frontendLoginPath,
		Metadata: map[string]string{
			flowdomain.FlowMetadataSAMLEntityID: issuer,
			flowdomain.FlowMetadataOriginalURL:  ctx.Request.URL.String(),
			flowdomain.FlowMetadataResumeTarget: ctx.Request.URL.RequestURI(),
		},
	}, time.Now())
}

// storeSAMLSSORequestContext persists the original SAML request in the encrypted cookie.
func (h *SAMLHandler) storeSAMLSSORequestContext(ctx *gin.Context, mgr cookie.Manager, issuer string) bool {
	samlFlowCtx := newSAMLFlowContext(mgr)
	samlFlowCtx.StoreRequest(issuer, ctx.Request.URL.String())

	if err := samlFlowCtx.Save(ctx); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to save session")

		return false
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

	return true
}

// normalizeSAMLRequestRemoteAddr removes the port for SAML assertion compatibility.
func normalizeSAMLRequestRemoteAddr(req *saml.IdpAuthnRequest) {
	if req == nil || req.HTTPRequest == nil {
		return
	}

	if ip, _, err := net.SplitHostPort(req.HTTPRequest.RemoteAddr); err == nil {
		req.HTTPRequest.RemoteAddr = ip
	}
}

// newSAMLAuthnSession creates the SAML session bound to the authenticated user.
func (h *SAMLHandler) newSAMLAuthnSession(username string) *saml.Session {
	samlSessionID, _ := util.GenerateRandomString(32)
	samlSessionIndex, _ := util.GenerateRandomString(32)

	return &saml.Session{
		ID:           samlSessionID,
		CreateTime:   time.Now().UTC(),
		ExpireTime:   time.Now().Add(h.deps.Cfg.GetIDP().SAML2.GetDefaultExpireTime()).UTC(),
		Index:        samlSessionIndex,
		UserName:     username,
		NameID:       username,
		NameIDFormat: h.deps.Cfg.GetIDP().SAML2.GetNameIDFormat(),
	}
}

// populateSAMLSessionAttributes copies allowed backend attributes into the SAML session.
func populateSAMLSessionAttributes(session *saml.Session, user *backend.User, samlSP *config.SAML2ServiceProvider) {
	if session == nil || user == nil || samlSP == nil {
		return
	}

	allowedAttrs := samlSP.GetAllowedAttributes()
	for k, v := range user.Attributes {
		if !shouldIncludeSAMLAttribute(k, v, allowedAttrs) {
			continue
		}

		session.CustomAttributes = append(session.CustomAttributes, samlStringAttribute(k, fmt.Sprintf("%v", v[0])))
	}

	appendFirstClassSAMLAttributes(&session.CustomAttributes, user, allowedAttrs)
}

// shouldIncludeSAMLAttribute applies SAML attribute filtering rules.
func shouldIncludeSAMLAttribute(name string, values []any, allowedAttrs []string) bool {
	if len(values) == 0 {
		return false
	}

	if name == definitions.ClaimGroups || name == definitions.LuaBackendResultGroupDistinguishedNames {
		return false
	}

	return len(allowedAttrs) == 0 || slices.Contains(allowedAttrs, name)
}

// samlStringAttribute creates a single-valued string SAML attribute.
func samlStringAttribute(name, value string) saml.Attribute {
	return saml.Attribute{
		Name: name,
		Values: []saml.AttributeValue{
			{
				Type:  samlAttributeTypeString,
				Value: value,
			},
		},
	}
}

// completeSAMLSSOFlow advances and completes the server-side flow after assertion creation.
func (h *SAMLHandler) completeSAMLSSOFlow(ctx *gin.Context, mgr cookie.Manager) {
	redisPrefix := h.deps.Cfg.GetServer().GetRedis().GetPrefix()

	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix, flowdomain.FlowStepCallback)
	completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix)
}

// renderSAMLPostBinding renders the browser auto-submit form for the SAML response.
func (h *SAMLHandler) renderSAMLPostBinding(ctx *gin.Context, form saml.IdpAuthnRequestForm) {
	data := h.samlPostPageData(ctx)
	data["AutoSubmitSAMLForm"] = true
	data["SAMLPostURL"] = form.URL
	data["SAMLResponse"] = form.SAMLResponse
	data["RelayState"] = form.RelayState

	ctx.HTML(http.StatusOK, "idp_saml_post.html", data)
}

// samlPostPageData builds localized template data for the SAML POST binding page.
func (h *SAMLHandler) samlPostPageData(ctx *gin.Context) gin.H {
	data := gin.H{
		templateDataLanguageTag:         frontendDefaultLanguageTag,
		templateDataLanguageCurrentName: "English",
		templateDataLanguagePassive:     []map[string]string{},
		templateDataCSPNonce:            securityheaders.NonceFromContext(ctx),
		templateDataConfirmTitle:        frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Confirmation"),
		templateDataConfirmYes:          frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Yes"),
		templateDataConfirmNo:           frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel"),
		templateDataIDPClientName:       "",
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

	return data
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

	h.logSLORequest(ctx)

	if !h.sloEnabled() {
		h.rejectDisabledSLO(ctx, binding)

		return
	}

	clientIP := util.RequestClientIPWithConfig(ctx, h.deps.Cfg, h.deps.Logger)
	if !h.allowSLORequest(clientIP) {
		h.rejectRateLimitedSLO(ctx, binding, messageType, clientIP)

		return
	}

	if ctx.Request.Method == http.MethodPost && ctx.Request.Body != nil {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, sloMaxInboundBodyBytes)
	}

	message, err := routeSLOInboundMessage(ctx.Request)
	if err != nil {
		h.rejectInvalidSLOPayload(ctx, binding, messageType, err)

		return
	}

	binding = message.Binding
	messageType = message.MessageType

	h.dispatchSLOMessage(ctx, message, binding, messageType)
}

// logSLORequest records the incoming SLO handler entry.
func (h *SAMLHandler) logSLORequest(ctx *gin.Context) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SLO request",
	)
}

// rejectDisabledSLO writes the disabled-endpoint response and audit entry.
func (h *SAMLHandler) rejectDisabledSLO(ctx *gin.Context, binding slodomain.Binding) {
	h.auditSLOEvent(
		ctx.Request.Context(),
		"request_rejected",
		"",
		"",
		"",
		samlMetricLabelBinding, binding,
		"reason", "slo_disabled",
	)
	ctx.String(http.StatusNotFound, "SAML SLO endpoint is disabled")
}

// rejectRateLimitedSLO writes the rate-limit response and abuse metrics.
func (h *SAMLHandler) rejectRateLimitedSLO(ctx *gin.Context, binding slodomain.Binding, messageType sloMessageType, clientIP string) {
	recordSLOAbuseRejection(sloAbuseReasonRateLimit, binding)
	recordSLOValidationError(sloValidationStageAbuseGuard, messageType, binding)
	h.auditSLOEvent(
		ctx.Request.Context(),
		"request_blocked",
		"",
		"",
		"",
		samlMetricLabelBinding, binding,
		"reason", sloAbuseReasonRateLimit,
		"client_ip", util.WithNotAvailable(strings.TrimSpace(clientIP)),
	)
	ctx.Header("Retry-After", "1")
	ctx.String(http.StatusTooManyRequests, "SAML SLO rate limit exceeded")
}

// rejectInvalidSLOPayload writes the payload validation failure response and metrics.
func (h *SAMLHandler) rejectInvalidSLOPayload(ctx *gin.Context, binding slodomain.Binding, messageType sloMessageType, err error) {
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
		samlMetricLabelBinding, binding,
		"stage", sloValidationStagePayload,
		"error", err.Error(),
	)
	ctx.String(http.StatusBadRequest, "Invalid SAML SLO payload: %v", err)
}

// dispatchSLOMessage routes a validated inbound SLO message by type.
func (h *SAMLHandler) dispatchSLOMessage(ctx *gin.Context, message *sloInboundMessage, binding slodomain.Binding, messageType sloMessageType) {
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
			samlMetricLabelBinding, binding,
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

func parseSLOMessageFromValues(values url.Values, binding slodomain.Binding) (*sloInboundMessage, error) {
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
	binding := slodomain.Binding("")
	if message != nil {
		binding = message.Binding
	}

	logoutRequest, err := h.validateInboundLogoutRequestSignature(ctx.Request, message)
	if err != nil {
		h.rejectLogoutRequest(ctx, binding, sloValidationStageSignature, "", "", "Invalid SAML LogoutRequest signature: %v", err)

		return
	}

	requestID := strings.TrimSpace(logoutRequest.ID)
	issuer := samlIssuerValue(logoutRequest.Issuer)

	if err = h.validateInboundLogoutRequestProtocol(ctx.Request.Context(), logoutRequest); err != nil {
		h.rejectLogoutRequest(ctx, binding, sloValidationStageProtocol, requestID, issuer, "Invalid SAML LogoutRequest protocol: %v", err)

		return
	}

	sloTransaction, err := h.newValidatedSLOTransaction(logoutRequest, message.Binding)
	if err != nil {
		h.rejectLogoutRequest(ctx, binding, sloValidationStageTransaction, requestID, issuer, "Invalid SAML LogoutRequest transaction: %v", err)

		return
	}

	h.completeValidatedLogoutRequest(ctx, message, logoutRequest, sloTransaction, binding, requestID, issuer)
}

// completeValidatedLogoutRequest performs local cleanup and sends the LogoutResponse.
func (h *SAMLHandler) completeValidatedLogoutRequest(
	ctx *gin.Context,
	message *sloInboundMessage,
	logoutRequest *saml.LogoutRequest,
	sloTransaction *slodomain.Transaction,
	binding slodomain.Binding,
	requestID string,
	issuer string,
) {
	account := samlLogoutRequestAccount(logoutRequest)

	h.logValidatedLogoutRequest(ctx, message, logoutRequest, sloTransaction, issuer)
	h.auditValidatedLogoutRequest(ctx, message, sloTransaction, binding, requestID, issuer)
	cleanupResult := h.performLocalSLOCleanupInternal(ctx, account, sloTransaction, false)
	terminalStatus := sloTerminalStatusFromCleanup(cleanupResult)
	recordSLOTerminalStatus(slodomain.SLODirectionSPInitiated, terminalStatus)
	h.auditLocalLogoutRequestCleanup(ctx, sloTransaction, binding, requestID, issuer, account, terminalStatus, cleanupResult)
	h.respondAndAuditLogoutRequest(ctx, message, logoutRequest, sloTransaction, binding, requestID, issuer, cleanupResult, terminalStatus)
}

// logValidatedLogoutRequest records the validated LogoutRequest routing context.
func (h *SAMLHandler) logValidatedLogoutRequest(
	ctx *gin.Context,
	message *sloInboundMessage,
	logoutRequest *saml.LogoutRequest,
	transaction *slodomain.Transaction,
	issuer string,
) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SLO routed LogoutRequest",
		samlMetricLabelBinding, message.Binding,
		"relay_state", util.WithNotAvailable(message.RelayState),
		"issuer", util.WithNotAvailable(issuer),
		"request_id", util.WithNotAvailable(logoutRequest.ID),
		"transaction_id", transaction.TransactionID,
	)
}

// auditValidatedLogoutRequest records successful LogoutRequest validation.
func (h *SAMLHandler) auditValidatedLogoutRequest(
	ctx *gin.Context,
	message *sloInboundMessage,
	transaction *slodomain.Transaction,
	binding slodomain.Binding,
	requestID string,
	issuer string,
) {
	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_request_validated",
		transaction.TransactionID,
		requestID,
		issuer,
		samlMetricLabelBinding, binding,
		"relay_state", util.WithNotAvailable(message.RelayState),
	)
}

// auditLocalLogoutRequestCleanup records local cleanup after a valid LogoutRequest.
func (h *SAMLHandler) auditLocalLogoutRequestCleanup(
	ctx *gin.Context,
	transaction *slodomain.Transaction,
	binding slodomain.Binding,
	requestID string,
	issuer string,
	account string,
	terminalStatus slodomain.Status,
	cleanupResult sloLocalCleanupResult,
) {
	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_request_local_cleanup",
		transaction.TransactionID,
		requestID,
		issuer,
		sloLocalCleanupAuditKeyvals(binding, terminalStatus, account, cleanupResult)...,
	)
}

// respondAndAuditLogoutRequest sends the LogoutResponse and records the outcome.
func (h *SAMLHandler) respondAndAuditLogoutRequest(
	ctx *gin.Context,
	message *sloInboundMessage,
	logoutRequest *saml.LogoutRequest,
	transaction *slodomain.Transaction,
	binding slodomain.Binding,
	requestID string,
	issuer string,
	cleanupResult sloLocalCleanupResult,
	terminalStatus slodomain.Status,
) {
	if err := h.respondToLogoutRequest(ctx, logoutRequest, message, cleanupResult); err != nil {
		h.auditSLOEvent(
			ctx.Request.Context(),
			"logout_response_failed",
			transaction.TransactionID,
			requestID,
			issuer,
			samlMetricLabelBinding, binding,
			"error", err.Error(),
		)
		ctx.String(http.StatusInternalServerError, "Failed to create SAML LogoutResponse: %v", err)

		return
	}

	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_response_sent",
		transaction.TransactionID,
		requestID,
		issuer,
		samlMetricLabelBinding, binding,
		samlMetricLabelStatus, terminalStatus,
	)
}

// samlLogoutRequestAccount returns the NameID account from a LogoutRequest.
func samlLogoutRequestAccount(logoutRequest *saml.LogoutRequest) string {
	if logoutRequest == nil || logoutRequest.NameID == nil {
		return ""
	}

	return strings.TrimSpace(logoutRequest.NameID.Value)
}

// rejectLogoutRequest records and writes a LogoutRequest validation failure.
func (h *SAMLHandler) rejectLogoutRequest(
	ctx *gin.Context,
	binding slodomain.Binding,
	stage string,
	requestID string,
	issuer string,
	responseFormat string,
	err error,
) {
	recordSLOValidationError(stage, sloMessageTypeRequest, binding)
	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_request_rejected",
		"",
		requestID,
		issuer,
		samlMetricLabelBinding, binding,
		"stage", stage,
		"error", err.Error(),
	)
	ctx.String(http.StatusBadRequest, responseFormat, err)
}

// sloLocalCleanupAuditKeyvals builds audit fields for local logout cleanup.
func sloLocalCleanupAuditKeyvals(
	binding slodomain.Binding,
	terminalStatus slodomain.Status,
	account string,
	cleanupResult sloLocalCleanupResult,
) []any {
	auditKeyvals := []any{
		samlMetricLabelBinding, binding,
		samlMetricLabelStatus, terminalStatus,
		"account", util.WithNotAvailable(account),
	}

	if cleanupResult.TransitionErr != nil {
		auditKeyvals = append(auditKeyvals, "cleanup_transition_error", cleanupResult.TransitionErr.Error())
	}

	if cleanupResult.ParticipantCleanupErr != nil {
		auditKeyvals = append(auditKeyvals, "participant_cleanup_error", cleanupResult.ParticipantCleanupErr.Error())
	}

	return auditKeyvals
}

func (h *SAMLHandler) handleLogoutResponse(ctx *gin.Context, message *sloInboundMessage) {
	binding := slodomain.Binding("")
	if message != nil {
		binding = message.Binding
	}

	logoutResponse, err := h.validateInboundLogoutResponseSignature(ctx.Request, message)
	if err != nil {
		h.rejectLogoutResponse(ctx, binding, sloValidationStageSignature, "", "", http.StatusBadRequest, "Invalid SAML LogoutResponse signature: %v", err)

		return
	}

	requestID := strings.TrimSpace(logoutResponse.InResponseTo)
	issuer := samlIssuerValue(logoutResponse.Issuer)

	if err = h.validateInboundLogoutResponseProtocol(logoutResponse); err != nil {
		h.rejectLogoutResponse(ctx, binding, sloValidationStageProtocol, requestID, issuer, http.StatusBadRequest, "Invalid SAML LogoutResponse protocol: %v", err)

		return
	}

	aggregation, err := h.applySLOFanoutLogoutResponse(ctx.Request.Context(), logoutResponse, message.RelayState)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errSLOFanoutStateUnavailable) {
			status = http.StatusInternalServerError
		}

		h.rejectLogoutResponse(ctx, binding, sloValidationStageCorrelation, requestID, issuer, status, "Cannot correlate SAML LogoutResponse: %v", err)

		return
	}

	h.logProcessedLogoutResponse(ctx, message, logoutResponse, aggregation, binding, requestID)
	ctx.String(http.StatusOK, "SAML LogoutResponse processed")
}

// rejectLogoutResponse records and writes a LogoutResponse validation failure.
func (h *SAMLHandler) rejectLogoutResponse(
	ctx *gin.Context,
	binding slodomain.Binding,
	stage string,
	requestID string,
	issuer string,
	status int,
	responseFormat string,
	err error,
) {
	recordSLOValidationError(stage, sloMessageTypeResponse, binding)
	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_response_rejected",
		"",
		requestID,
		issuer,
		samlMetricLabelBinding, binding,
		"stage", stage,
		"error", err.Error(),
	)
	ctx.String(status, responseFormat, err)
}

// logProcessedLogoutResponse records successful fanout aggregation diagnostics and audit data.
func (h *SAMLHandler) logProcessedLogoutResponse(
	ctx *gin.Context,
	message *sloInboundMessage,
	logoutResponse *saml.LogoutResponse,
	aggregation *sloFanoutAggregationResult,
	binding slodomain.Binding,
	requestID string,
) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SLO routed LogoutResponse",
		samlMetricLabelBinding, message.Binding,
		"relay_state", util.WithNotAvailable(message.RelayState),
		"issuer", util.WithNotAvailable(samlIssuerValue(logoutResponse.Issuer)),
		"in_response_to", util.WithNotAvailable(logoutResponse.InResponseTo),
		"transaction_id", util.WithNotAvailable(aggregation.TransactionID),
		"participant", util.WithNotAvailable(aggregation.ParticipantEntity),
		"pending", aggregation.PendingCount,
		"success_count", aggregation.SuccessCount,
		"failure_count", aggregation.FailureCount,
		samlMetricLabelStatus, aggregation.Status,
		"final", aggregation.Final,
	)

	h.auditSLOEvent(
		ctx.Request.Context(),
		"logout_response_processed",
		aggregation.TransactionID,
		requestID,
		aggregation.ParticipantEntity,
		samlMetricLabelBinding, binding,
		samlMetricLabelStatus, aggregation.Status,
		"success_count", aggregation.SuccessCount,
		"failure_count", aggregation.FailureCount,
		"pending", aggregation.PendingCount,
		"final", aggregation.Final,
	)
}

func (h *SAMLHandler) newValidatedSLOTransaction(
	logoutRequest *saml.LogoutRequest,
	binding slodomain.Binding,
) (*slodomain.Transaction, error) {
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
	transaction *slodomain.Transaction,
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
	transaction *slodomain.Transaction,
	redirectToLoggedOut bool,
) sloLocalCleanupResult {
	mgr := cookie.GetManager(ctx)
	account := sloCleanupAccount(accountHint, mgr)
	result := sloLocalCleanupResult{
		Account: account,
	}

	if transaction != nil {
		result.TransitionErr = h.transitionSLOTransactionLocalDone(ctx, transaction, account)
	}

	if mgr != nil {
		h.cleanupSLOBrowserFlowState(ctx, mgr)
	}

	core.SessionCleaner(ctx)
	result.ParticipantCleanupErr = h.cleanupSLOParticipantSessions(ctx, account)
	core.ClearBrowserCookies(ctx)

	if redirectToLoggedOut {
		ctx.Redirect(http.StatusFound, "/logged_out")
	}

	return result
}

// sloCleanupAccount chooses the explicit account hint before falling back to the session account.
func sloCleanupAccount(accountHint string, mgr cookie.Manager) string {
	account := strings.TrimSpace(accountHint)
	if account != "" || mgr == nil {
		return account
	}

	return strings.TrimSpace(mgr.GetString(definitions.SessionKeyAccount, ""))
}

// transitionSLOTransactionLocalDone records local cleanup completion on the transaction.
func (h *SAMLHandler) transitionSLOTransactionLocalDone(
	ctx *gin.Context,
	transaction *slodomain.Transaction,
	account string,
) error {
	if transaction.Account == "" {
		transaction.Account = account
	}

	err := transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if err == nil {
		return nil
	}

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

	return err
}

// cleanupSLOBrowserFlowState clears browser-bound login, MFA, and flow state.
func (h *SAMLHandler) cleanupSLOBrowserFlowState(ctx *gin.Context, mgr cookie.Manager) {
	var redisClient rediscli.Client
	if h != nil && h.deps != nil {
		redisClient = h.deps.Redis
	}

	abortFlow(ctx.Request.Context(), mgr, redisClient, h.redisPrefix())
	CleanupMFAState(mgr)
	flowdomain.ClearRequireMFAContext(mgr)
}

// cleanupSLOParticipantSessions deletes persisted SLO participant sessions for the account.
func (h *SAMLHandler) cleanupSLOParticipantSessions(ctx *gin.Context, account string) error {
	err := h.deleteSLOParticipantSessionsByAccount(ctx.Request.Context(), account)
	if err == nil {
		return nil
	}

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

	return err
}

func appendFirstClassSAMLAttributes(attributes *[]saml.Attribute, user *backend.User, allowedAttrs []string) {
	if attributes == nil || user == nil || len(allowedAttrs) == 0 {
		return
	}

	appendSAMLStringValues(attributes, definitions.ClaimGroups, user.Groups, allowedAttrs)
	appendSAMLStringValues(attributes, definitions.LuaBackendResultGroupDistinguishedNames, user.GroupDistinguishedNames, allowedAttrs)
}

func appendSAMLStringValues(attributes *[]saml.Attribute, name string, values []string, allowedAttrs []string) {
	if len(values) == 0 || !slices.Contains(allowedAttrs, name) {
		return
	}

	samlValues := make([]saml.AttributeValue, 0, len(values))
	for _, value := range values {
		samlValues = append(samlValues, saml.AttributeValue{
			Type:  samlAttributeTypeString,
			Value: value,
		})
	}

	*attributes = append(*attributes, saml.Attribute{
		Name:   name,
		Values: samlValues,
	})
}

func (h *SAMLHandler) redisPrefix() string {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || h.deps.Cfg.GetServer() == nil {
		return ""
	}

	return h.deps.Cfg.GetServer().GetRedis().GetPrefix()
}
