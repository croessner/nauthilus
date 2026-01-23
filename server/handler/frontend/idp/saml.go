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
	"fmt"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// SAMLHandler handles SAML 2.0 protocol requests.
type SAMLHandler struct {
	deps   *deps.Deps
	idp    *idp.NauthilusIdP
	tracer monittrace.Tracer
}

// NewSAMLHandler creates a new SAMLHandler.
func NewSAMLHandler(d *deps.Deps, idp *idp.NauthilusIdP) *SAMLHandler {
	return &SAMLHandler{
		deps:   d,
		idp:    idp,
		tracer: monittrace.New("nauthilus/idp/saml"),
	}
}

// Register adds SAML routes to the router.
func (h *SAMLHandler) Register(router gin.IRouter) {
	router.GET("/saml/metadata", h.Metadata)
	router.GET("/saml/sso", h.SSO)
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

	samlCfg := h.deps.Cfg.GetIdP().SAML2
	entityID := samlCfg.EntityID
	issuer := h.deps.Cfg.GetIdP().OIDC.Issuer

	// Clean up certificate for metadata (remove headers and newlines)
	cert := samlCfg.Certificate
	cert = strings.ReplaceAll(cert, "-----BEGIN CERTIFICATE-----", "")
	cert = strings.ReplaceAll(cert, "-----END CERTIFICATE-----", "")
	cert = strings.ReplaceAll(cert, "\n", "")
	cert = strings.ReplaceAll(cert, "\r", "")
	cert = strings.TrimSpace(cert)

	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/saml/sso"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, entityID, cert, issuer)

	ctx.Data(http.StatusOK, "application/xml", []byte(metadata))
}

// SSO handles the SAML Single Sign-On request (Redirect Binding).
func (h *SAMLHandler) SSO(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "saml.sso")
	defer sp.End()

	ctx.String(http.StatusNotImplemented, "Not implemented yet")
}
