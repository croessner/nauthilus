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
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
)

// enforceSAMLAuthnRequestSignature applies the configured SP AuthnRequest policy.
func (h *SAMLHandler) enforceSAMLAuthnRequestSignature(httpRequest *http.Request, request *saml.IdpAuthnRequest, issuer string) error {
	if httpRequest == nil || httpRequest.URL == nil {
		return fmt.Errorf("authn request is missing HTTP context")
	}

	if request == nil {
		return fmt.Errorf("authn request is missing")
	}

	sp, ok := h.findConfiguredSAMLServiceProvider(issuer)
	if !ok {
		return fmt.Errorf("unknown SAML service provider issuer %q", issuer)
	}

	binding, err := authnRequestBinding(httpRequest.Method)
	if err != nil {
		return err
	}

	shouldValidate, err := shouldValidateInboundAuthnRequestSignature(binding, httpRequest.URL.RawQuery, request.RequestBuffer, sp.AreAuthnRequestsSigned())
	if err != nil {
		return err
	}

	if !shouldValidate {
		return nil
	}

	certs, err := h.resolveAuthnRequestSigningCerts(issuer)
	if err != nil {
		return err
	}

	return validateAuthnRequestSignatureForBinding(binding, httpRequest.URL.RawQuery, request.RequestBuffer, certs)
}

// authnRequestBinding maps the HTTP method to the SAML binding used by the request.
func authnRequestBinding(method string) (slodomain.Binding, error) {
	switch method {
	case http.MethodGet:
		return slodomain.SLOBindingRedirect, nil
	case http.MethodPost:
		return slodomain.SLOBindingPost, nil
	default:
		return "", fmt.Errorf("unsupported AuthnRequest binding method %q", method)
	}
}

// shouldValidateInboundAuthnRequestSignature decides if a present or required signature must be checked.
func shouldValidateInboundAuthnRequestSignature(binding slodomain.Binding, rawQuery string, requestXML []byte, required bool) (bool, error) {
	return shouldValidateInboundSAMLRequestSignature(binding, rawQuery, requestXML, required, "AuthnRequest")
}

// validateAuthnRequestSignatureForBinding validates an AuthnRequest signature for its binding.
func validateAuthnRequestSignatureForBinding(
	binding slodomain.Binding,
	rawQuery string,
	requestXML []byte,
	certs []*x509.Certificate,
) error {
	switch binding {
	case slodomain.SLOBindingRedirect:
		return validateRedirectAuthnRequestSignature(rawQuery, certs)
	case slodomain.SLOBindingPost:
		return validateXMLAuthnRequestSignature(requestXML, certs)
	default:
		return fmt.Errorf("unsupported AuthnRequest binding %q", binding)
	}
}

// resolveAuthnRequestSigningCerts loads signing certificates for AuthnRequest validation.
func (h *SAMLHandler) resolveAuthnRequestSigningCerts(issuer string) ([]*x509.Certificate, error) {
	return h.resolveLogoutRequestSigningCerts(issuer)
}

// validateRedirectAuthnRequestSignature verifies a Redirect-binding AuthnRequest signature.
func validateRedirectAuthnRequestSignature(rawQuery string, certs []*x509.Certificate) error {
	parts, err := parseRedirectSLOSignatureParts(rawQuery, "SAMLRequest", true)
	if err != nil {
		return err
	}

	return verifyRedirectSLOSignature(parts, certs, "authn request")
}

// validateXMLAuthnRequestSignature verifies an enveloped XML AuthnRequest signature.
func validateXMLAuthnRequestSignature(requestXML []byte, certs []*x509.Certificate) error {
	return validateXMLLogoutSignature(requestXML, certs, "AuthnRequest", "authn request")
}
