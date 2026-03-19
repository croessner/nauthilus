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
	"crypto"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/server/config"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

const samlEntityIssuerFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

func (h *SAMLHandler) respondToLogoutRequest(
	ctx *gin.Context,
	logoutRequest *saml.LogoutRequest,
	inboundMessage *sloInboundMessage,
	cleanupResult sloLocalCleanupResult,
) error {
	if ctx == nil {
		return fmt.Errorf("logout response context is missing")
	}

	if logoutRequest == nil {
		return fmt.Errorf("logout request payload is missing")
	}

	if inboundMessage == nil {
		return fmt.Errorf("logout request routing context is missing")
	}

	status := samlLogoutResponseStatusFromCleanup(cleanupResult)
	response, err := h.buildSignedLogoutResponse(logoutRequest, status)
	if err != nil {
		return err
	}

	return h.writeSignedLogoutResponse(ctx, response, inboundMessage.Binding, inboundMessage.RelayState)
}

func samlLogoutResponseStatusFromCleanup(cleanupResult sloLocalCleanupResult) saml.Status {
	if cleanupResult.TransitionErr == nil && cleanupResult.ParticipantCleanupErr == nil {
		return saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		}
	}

	statusCode := saml.StatusCode{
		Value: saml.StatusResponder,
	}
	statusMessage := "local logout cleanup failed"

	if cleanupResult.ParticipantCleanupErr != nil {
		statusCode.StatusCode = &saml.StatusCode{
			Value: saml.StatusPartialLogout,
		}
		statusMessage = "local logout completed with partial participant cleanup"
	}

	return saml.Status{
		StatusCode: statusCode,
		StatusMessage: &saml.StatusMessage{
			Value: statusMessage,
		},
	}
}

func (h *SAMLHandler) buildSignedLogoutResponse(logoutRequest *saml.LogoutRequest, status saml.Status) (*saml.LogoutResponse, error) {
	if logoutRequest == nil {
		return nil, fmt.Errorf("logout request payload is missing")
	}

	requestID := strings.TrimSpace(logoutRequest.ID)
	if requestID == "" {
		return nil, fmt.Errorf("logout request id is missing")
	}

	issuer := ""
	if logoutRequest.Issuer != nil {
		issuer = strings.TrimSpace(logoutRequest.Issuer.Value)
	}

	if issuer == "" {
		return nil, fmt.Errorf("logout request issuer is missing")
	}

	destination, err := h.resolveLogoutResponseDestination(issuer)
	if err != nil {
		return nil, err
	}

	idpObj, err := h.getSAMLIdP()
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(idpObj.MetadataURL.String()) == "" {
		return nil, fmt.Errorf("idp metadata url is not configured")
	}

	response := &saml.LogoutResponse{
		ID:           "id-" + ksuid.New().String(),
		InResponseTo: requestID,
		Version:      "2.0",
		IssueInstant: saml.TimeNow().UTC(),
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: samlEntityIssuerFormat,
			Value:  idpObj.MetadataURL.String(),
		},
		Status: status,
	}

	if err = h.signLogoutResponse(response, idpObj); err != nil {
		return nil, err
	}

	return response, nil
}

func (h *SAMLHandler) signLogoutResponse(response *saml.LogoutResponse, idpObj *saml.IdentityProvider) error {
	if response == nil {
		return fmt.Errorf("logout response payload is missing")
	}

	if idpObj == nil {
		return fmt.Errorf("idp context is missing")
	}

	signer, ok := idpObj.Key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("idp key type %T does not support signing", idpObj.Key)
	}

	signatureMethod := strings.TrimSpace(idpObj.SignatureMethod)
	if signatureMethod == "" {
		signatureMethod = h.deps.Cfg.GetIdP().SAML2.GetSignatureMethod()
	}

	if isWeakSHA1SignatureMethodSLO(signatureMethod) {
		return fmt.Errorf("unsupported SAML logout response signature algorithm %q", signatureMethod)
	}

	spSigner := &saml.ServiceProvider{
		Key:             signer,
		Certificate:     idpObj.Certificate,
		SignatureMethod: signatureMethod,
	}

	if err := spSigner.SignLogoutResponse(response); err != nil {
		return fmt.Errorf("cannot sign LogoutResponse: %w", err)
	}

	return nil
}

func (h *SAMLHandler) writeSignedLogoutResponse(
	ctx *gin.Context,
	response *saml.LogoutResponse,
	binding slodomain.SLOBinding,
	relayState string,
) error {
	if ctx == nil {
		return fmt.Errorf("logout response context is missing")
	}

	if response == nil {
		return fmt.Errorf("logout response payload is missing")
	}

	binding = resolveLogoutResponseBinding(binding)

	switch binding {
	case slodomain.SLOBindingRedirect:
		redirectTarget := response.Redirect(relayState)
		if redirectTarget == nil {
			return fmt.Errorf("cannot encode redirect LogoutResponse target")
		}

		ctx.Redirect(http.StatusFound, redirectTarget.String())
	case slodomain.SLOBindingPost:
		ctx.Data(http.StatusOK, "text/html; charset=utf-8", response.Post(relayState))
	default:
		return fmt.Errorf("unsupported SLO response binding %q", binding)
	}

	return nil
}

func resolveLogoutResponseBinding(binding slodomain.SLOBinding) slodomain.SLOBinding {
	switch binding {
	case slodomain.SLOBindingPost, slodomain.SLOBindingRedirect:
		return binding
	default:
		return slodomain.SLOBindingRedirect
	}
}

func (h *SAMLHandler) resolveLogoutResponseDestination(issuer string) (string, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return "", fmt.Errorf("logout response issuer is missing")
	}

	if sp, ok := h.findConfiguredSAMLServiceProvider(issuer); ok {
		sloURL := strings.TrimSpace(sp.SLOURL)
		if sloURL != "" {
			parsedSLOURL, err := parseAbsoluteURL(sloURL)
			if err != nil {
				return "", fmt.Errorf("invalid SAML SLOURL for issuer %q: %w", issuer, err)
			}

			return parsedSLOURL.String(), nil
		}
	}

	parsedIssuer, err := parseAbsoluteURL(issuer)
	if err != nil {
		return "", fmt.Errorf("logout response destination for issuer %q is not configured", issuer)
	}

	return parsedIssuer.String(), nil
}

func (h *SAMLHandler) findConfiguredSAMLServiceProvider(entityID string) (*config.SAML2ServiceProvider, bool) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return nil, false
	}

	serviceProviders := h.deps.Cfg.GetIdP().SAML2.ServiceProviders

	for index := range serviceProviders {
		if strings.TrimSpace(serviceProviders[index].EntityID) == entityID {
			return &serviceProviders[index], true
		}
	}

	return nil, false
}

func parseAbsoluteURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, err
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("absolute URL required")
	}

	parsedURL.Fragment = ""

	return parsedURL, nil
}
