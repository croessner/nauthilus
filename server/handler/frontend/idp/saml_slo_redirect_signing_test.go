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

package idp

import (
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/v4/server/idp/slo"
	"github.com/gin-gonic/gin"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
)

const (
	logoutResponseSigningSPEntityID = "https://sp.example.com/saml/metadata"
	logoutResponseSigningSPSLOURL   = "https://sp.example.com/saml/slo"
	logoutResponseSigningRequestID  = "id-outbound-logout-request"
	logoutResponseSigningRelayState = "relay-outbound"
)

// logoutResponseSigningFixture holds an IdP handler that answers one SP LogoutRequest.
type logoutResponseSigningFixture struct {
	handler       *SAMLHandler
	idpCert       *x509.Certificate
	logoutRequest *saml.LogoutRequest
}

// newLogoutResponseSigningFixture builds a handler with an IdP signing key and one SP with an SLO URL.
func newLogoutResponseSigningFixture(t *testing.T) logoutResponseSigningFixture {
	t.Helper()

	_, _, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "auth.example.com")

	handler := newSignedSLOTestHandler(
		t, nil, logoutResponseSigningSPEntityID, logoutResponseSigningSPSLOURL,
		spCertPEM, idpCertPEM, mustEncodeRSAPrivateKeyPEM(t, idpKey),
	)

	return logoutResponseSigningFixture{
		handler: handler,
		idpCert: idpCert,
		logoutRequest: newSignedRedirectSLOLogoutRequest(
			logoutResponseSigningRequestID, logoutResponseSigningSPEntityID, "alice@example.com",
		),
	}
}

// respond answers the fixture LogoutRequest for the given binding and returns the HTTP recording.
func (f logoutResponseSigningFixture) respond(t *testing.T, binding slodomain.Binding) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/saml/slo", nil)

	err := f.handler.respondToLogoutRequest(ctx, f.logoutRequest, &sloInboundMessage{
		MessageType: sloMessageTypeRequest,
		Binding:     binding,
		RelayState:  logoutResponseSigningRelayState,
	}, sloLocalCleanupResult{})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return w
}

// TestSAMLHandler_respondToLogoutRequest_RedirectQuerySignature proves Redirect LogoutResponses carry a
// verifiable SigAlg/Signature pair (saml-bindings §3.4.4.1) and no enveloped XML signature.
func TestSAMLHandler_respondToLogoutRequest_RedirectQuerySignature(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newLogoutResponseSigningFixture(t)
	w := fixture.respond(t, slodomain.SLOBindingRedirect)

	if !assert.Equal(t, http.StatusFound, w.Code) {
		t.FailNow()
	}

	location, err := url.Parse(w.Header().Get("Location"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, logoutResponseSigningSPSLOURL, location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, logoutResponseSigningRelayState, location.Query().Get("RelayState"))

	parts, err := parseRedirectSLOSignatureParts(location.RawQuery, "SAMLResponse", true)
	if !assert.NoError(t, err, "redirect LogoutResponse must carry a query-string signature") {
		t.FailNow()
	}

	assert.Equal(t, fixture.handler.deps.Cfg.GetIDP().SAML2.GetSignatureMethod(), parts.SigAlgValue)
	assert.NoError(t, verifyRedirectSLOSignature(parts, []*x509.Certificate{fixture.idpCert}, "logout response"))

	responseXML, logoutResponse, err := decodeLogoutResponsePayload(slodomain.SLOBindingRedirect, location.Query().Get("SAMLResponse"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, logoutResponseSigningRequestID, logoutResponse.InResponseTo)
	assert.Equal(t, logoutResponseSigningSPSLOURL, logoutResponse.Destination)
	assert.Equal(t, saml.StatusSuccess, logoutResponse.Status.StatusCode.Value)

	hasXMLSignature, err := xmlSLOHasSignature(responseXML)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.False(t, hasXMLSignature, "HTTP-Redirect payload must not embed an XML signature")

	tamperedQuery := strings.Replace(
		location.RawQuery, "RelayState="+logoutResponseSigningRelayState, "RelayState=tampered", 1,
	)

	tamperedParts, err := parseRedirectSLOSignatureParts(tamperedQuery, "SAMLResponse", true)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.ErrorContains(
		t,
		verifyRedirectSLOSignature(tamperedParts, []*x509.Certificate{fixture.idpCert}, "logout response"),
		"invalid redirect logout response signature",
	)
}

// TestSAMLHandler_respondToLogoutRequest_PostXMLSignature proves POST LogoutResponses keep the enveloped XML signature.
func TestSAMLHandler_respondToLogoutRequest_PostXMLSignature(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newLogoutResponseSigningFixture(t)
	w := fixture.respond(t, slodomain.SLOBindingPost)

	if !assert.Equal(t, http.StatusOK, w.Code) {
		t.FailNow()
	}

	assert.Equal(t, logoutResponseSigningRelayState, mustExtractHiddenFormValue(t, w.Body.String(), "RelayState"))

	responseXML, err := base64.StdEncoding.DecodeString(mustExtractHiddenFormValue(t, w.Body.String(), "SAMLResponse"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.NoError(t, validateXMLLogoutResponseSignature(responseXML, []*x509.Certificate{fixture.idpCert}))
}

// newRequiredSLOSignatureHandler builds a handler whose single SP must sign LogoutRequests and LogoutResponses.
func newRequiredSLOSignatureHandler(spCertPEM []byte) *SAMLHandler {
	required := true

	return NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID:              logoutResponseSigningSPEntityID,
					ACSURL:                "https://sp.example.com/saml/acs",
					Cert:                  string(spCertPEM),
					LogoutRequestsSigned:  &required,
					LogoutResponsesSigned: &required,
				},
			},
		},
		Logger: slog.Default(),
	}, nil)
}

// TestSAMLHandler_validateInboundRedirectSLOSignature_RequiredPolicy proves the configured signing policy
// rejects unsigned Redirect messages while query-signed messages remain accepted.
func TestSAMLHandler_validateInboundRedirectSLOSignature_RequiredPolicy(t *testing.T) {
	spKey, spCert, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
	handler := newRequiredSLOSignatureHandler(spCertPEM)

	logoutRequest := newSignedRedirectSLOLogoutRequest("id-policy-request", logoutResponseSigningSPEntityID, "alice@example.com")
	logoutRequest.Destination = "https://auth.example.com/saml/slo"
	logoutResponse := mustBuildSignedLogoutResponse(
		t, spKey, spCert, logoutResponseSigningSPEntityID, "https://auth.example.com/saml/slo",
		"id-policy-request", dsig.RSASHA256SignatureMethod, saml.Status{},
	)
	unsignedResponse := *logoutResponse
	unsignedResponse.Signature = nil
	unsignedResponse.IssueInstant = time.Now().UTC()

	requestCases := []sloRedirectSignatureCase{
		{
			name: "unsigned request rejected",
			target: "/saml/slo?" + mustBuildRedirectSAMLQuery(
				t, "SAMLRequest", logoutRequest.Element(), "relay-state",
			),
			wantErr: "redirect binding signature is required",
		},
		{
			name: "query-signed request accepted",
			target: mustBuildSignedRedirectLogoutTarget(
				t, "/saml/slo", logoutRequest, "relay-state", dsig.RSASHA256SignatureMethod, spKey,
			),
		},
	}

	assertSLOInboundRedirectSignatureCases(t, requestCases, func(req *http.Request, message *sloInboundMessage) error {
		_, err := handler.validateInboundLogoutRequestSignature(req, message)

		return err
	})

	responseCases := []sloRedirectSignatureCase{
		{
			name:    "unsigned response rejected",
			target:  mustBuildRedirectLogoutResponseTarget(t, &unsignedResponse, "relay-state"),
			wantErr: "logout response XML signature is required",
		},
		{
			name: "query-signed response accepted",
			target: mustBuildQuerySignedRedirectLogoutResponseTarget(
				t, logoutResponse, "relay-state", dsig.RSASHA256SignatureMethod, spKey,
			),
		},
	}

	assertSLOInboundRedirectSignatureCases(t, responseCases, func(req *http.Request, message *sloInboundMessage) error {
		_, err := handler.validateInboundLogoutResponseSignature(req, message)

		return err
	})
}
