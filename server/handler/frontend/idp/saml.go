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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// SAMLHandler handles SAML 2.0 protocol requests.
type SAMLHandler struct {
	deps   *deps.Deps
	idp    *idp.NauthilusIdP
	store  sessions.Store
	tracer monittrace.Tracer
}

type samlLogger struct {
	logger *slog.Logger
}

func (l *samlLogger) Printf(format string, v ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, v...))
}

func (l *samlLogger) Print(v ...interface{}) {
	l.logger.Info(fmt.Sprint(v...))
}

func (l *samlLogger) Println(v ...interface{}) {
	l.logger.Info(fmt.Sprintln(v...))
}

func (l *samlLogger) Fatal(v ...interface{}) {
	l.logger.Error(fmt.Sprint(v...))

	os.Exit(1)
}

func (l *samlLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, v...))

	os.Exit(1)
}

func (l *samlLogger) Fatalln(v ...interface{}) {
	l.logger.Error(fmt.Sprintln(v...))

	os.Exit(1)
}

func (l *samlLogger) Panic(v ...interface{}) {
	s := fmt.Sprint(v...)

	l.logger.Error(s)

	panic(s)
}

func (l *samlLogger) Panicf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)

	l.logger.Error(s)

	panic(s)
}

func (l *samlLogger) Panicln(v ...interface{}) {
	s := fmt.Sprintln(v...)

	l.logger.Error(s)

	panic(s)
}

// NewSAMLHandler creates a new SAMLHandler.
func NewSAMLHandler(sessStore sessions.Store, d *deps.Deps, idp *idp.NauthilusIdP) *SAMLHandler {
	return &SAMLHandler{
		deps:   d,
		idp:    idp,
		store:  sessStore,
		tracer: monittrace.New("nauthilus/idp/saml"),
	}
}

// GetServiceProvider returns the Service Provider metadata for the given entity ID.
func (h *SAMLHandler) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	sp, ok := h.idp.FindSAMLServiceProvider(serviceProviderID)
	if !ok {
		return nil, os.ErrNotExist
	}

	return &saml.EntityDescriptor{
		EntityID: sp.EntityID,
		SPSSODescriptors: []saml.SPSSODescriptor{
			{
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
			},
		},
	}, nil
}

func (h *SAMLHandler) getSAMLIdP(ctx *gin.Context) (*saml.IdentityProvider, error) {
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
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		Logger:                  &samlLogger{logger: h.deps.Logger},
	}, nil
}

// Register adds SAML routes to the router.
func (h *SAMLHandler) Register(router gin.IRouter) {
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIdP)
		ctx.Next()
	}, mdlua.LuaContextMiddleware())

	sessionMW := sessions.Sessions(definitions.SessionName, h.store)

	router.GET("/saml/metadata", h.Metadata)
	router.GET("/saml/sso", sessionMW, h.SSO)
	router.GET("/saml/slo", sessionMW, h.SLO)
	router.POST("/saml/slo", sessionMW, h.SLO)
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

	idpObj, err := h.getSAMLIdP(ctx)
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

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SSO request",
	)

	idpObj, err := h.getSAMLIdP(ctx)
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

	session := sessions.Default(ctx)
	account := session.Get(definitions.CookieAccount)

	if account == nil {
		// User not logged in, redirect to login page
		loginURL := "/login"
		// Append original request to return_to
		originalURL := ctx.Request.URL.String()

		ctx.Redirect(http.StatusFound, loginURL+"?return_to="+url.QueryEscape(originalURL)+"&protocol=saml")

		return
	}

	// User is logged in
	username := account.(string)

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
		ExpireTime:   time.Now().Add(time.Hour).UTC(),
		Index:        samlSessionIndex,
		UserName:     username,
		NameID:       username,
		NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
	}

	// Add attributes
	for k, v := range user.Attributes {
		if len(v) > 0 {
			samlSession.CustomAttributes = append(samlSession.CustomAttributes, saml.Attribute{
				Name: k,
				Values: []saml.AttributeValue{
					{
						Value: fmt.Sprintf("%v", v[0]),
					},
				},
			})
		}
	}

	req.Now = time.Now().UTC()

	assertionMaker := saml.DefaultAssertionMaker{}
	if err := assertionMaker.MakeAssertion(req, samlSession); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to make SAML assertion: %v", err)

		return
	}

	ctx.Header("Content-Type", "text/html; charset=utf-8")
	ctx.Status(http.StatusOK)

	if err := req.WriteResponse(ctx.Writer); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to write SAML response: %v", err)

		return
	}
}

// SLO handles the SAML Single Logout request.
func (h *SAMLHandler) SLO(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "saml.slo")
	defer sp.End()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "SAML SLO request",
	)

	core.ClearBrowserCookies(ctx)

	ctx.Redirect(http.StatusFound, "/logged_out")
}
