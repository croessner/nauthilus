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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v4/server/config"
	slodomain "github.com/croessner/nauthilus/v4/server/idp/slo"
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

	idpObj, err := h.getSAMLIDP()
	if err != nil {
		return err
	}

	signingSP, err := h.newSLOSigningServiceProvider(idpObj)
	if err != nil {
		return err
	}

	status := samlLogoutResponseStatusFromCleanup(cleanupResult)

	response, err := h.buildLogoutResponse(logoutRequest, status, idpObj)
	if err != nil {
		return err
	}

	return writeSignedLogoutResponse(ctx, response, signingSP, inboundMessage.Binding, inboundMessage.RelayState)
}

func samlLogoutResponseStatusFromCleanup(cleanupResult sloLocalCleanupResult) saml.Status {
	if cleanupResult.TransitionErr == nil && cleanupResult.SessionRevocationErr == nil &&
		cleanupResult.ParticipantCleanupErr == nil {
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
	if cleanupResult.SessionRevocationErr != nil {
		statusMessage = "local browser session revocation failed"
	}

	if cleanupResult.SessionRevocationErr == nil && cleanupResult.ParticipantCleanupErr != nil {
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

// buildLogoutResponse creates the unsigned LogoutResponse; the binding writer applies the matching signature.
func (h *SAMLHandler) buildLogoutResponse(
	logoutRequest *saml.LogoutRequest,
	status saml.Status,
	idpObj *saml.IdentityProvider,
) (*saml.LogoutResponse, error) {
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

	if idpObj == nil {
		return nil, fmt.Errorf("idp context is missing")
	}

	if strings.TrimSpace(idpObj.MetadataURL.String()) == "" {
		return nil, fmt.Errorf("idp metadata url is not configured")
	}

	response := &saml.LogoutResponse{
		ID:           "id-" + ksuid.New().String(),
		InResponseTo: requestID,
		Version:      samlProtocolVersion,
		IssueInstant: saml.TimeNow().UTC(),
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: samlEntityIssuerFormat,
			Value:  idpObj.MetadataURL.String(),
		},
		Status: status,
	}

	return response, nil
}

// writeSignedLogoutResponse signs and writes a LogoutResponse for its binding: HTTP-Redirect carries a
// detached query-string signature (saml-bindings-2.0-os §3.4.4.1), HTTP-POST an enveloped XML signature.
func writeSignedLogoutResponse(
	ctx *gin.Context,
	response *saml.LogoutResponse,
	signingSP *saml.ServiceProvider,
	binding slodomain.Binding,
	relayState string,
) error {
	if ctx == nil {
		return fmt.Errorf("logout response context is missing")
	}

	if response == nil {
		return fmt.Errorf("logout response payload is missing")
	}

	if signingSP == nil {
		return fmt.Errorf("logout response signer is missing")
	}

	binding = resolveLogoutResponseBinding(binding)

	switch binding {
	case slodomain.SLOBindingRedirect:
		redirectTarget, err := buildSignedRedirectLogoutResponseURL(response, relayState, signingSP)
		if err != nil {
			return fmt.Errorf("cannot encode redirect LogoutResponse target: %w", err)
		}

		ctx.Redirect(http.StatusFound, redirectTarget)
	case slodomain.SLOBindingPost:
		if err := signingSP.SignLogoutResponse(response); err != nil {
			return fmt.Errorf("cannot sign LogoutResponse: %w", err)
		}

		ctx.Data(http.StatusOK, "text/html; charset=utf-8", response.Post(relayState))
	default:
		return fmt.Errorf("unsupported SLO response binding %q", binding)
	}

	return nil
}

func resolveLogoutResponseBinding(binding slodomain.Binding) slodomain.Binding {
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

	sp, ok := h.findConfiguredSAMLServiceProvider(issuer)
	if !ok {
		return "", fmt.Errorf("logout response destination for issuer %q is not configured", issuer)
	}

	sloURL := strings.TrimSpace(sp.SLOURL)
	if sloURL == "" {
		return "", fmt.Errorf("logout response destination for issuer %q requires a configured identity.saml.service_providers[].slo_url", issuer)
	}

	parsedSLOURL, err := parseAbsoluteURL(sloURL)
	if err != nil {
		return "", fmt.Errorf("invalid SAML SLOURL for issuer %q: %w", issuer, err)
	}

	return parsedSLOURL.String(), nil
}

func (h *SAMLHandler) findConfiguredSAMLServiceProvider(entityID string) (*config.SAML2ServiceProvider, bool) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return nil, false
	}

	return config.FindSAMLServiceProviderByEntityID(h.deps.Cfg.GetIDP().SAML2.ServiceProviders, entityID)
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
