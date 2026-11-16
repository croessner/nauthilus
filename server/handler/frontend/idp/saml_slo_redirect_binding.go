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
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

// HTTP-Redirect binding query parameters (saml-bindings-2.0-os §3.4.4).
const (
	samlRedirectRequestParam    = "SAMLRequest"
	samlRedirectResponseParam   = "SAMLResponse"
	samlRedirectRelayStateParam = "RelayState"
	samlRedirectSigAlgParam     = "SigAlg"
	samlRedirectSignatureParam  = "Signature"
)

// buildSignedRedirectLogoutRequestURL encodes an outbound LogoutRequest for the HTTP-Redirect binding.
func buildSignedRedirectLogoutRequestURL(
	logoutRequest *saml.LogoutRequest,
	relayState string,
	signingSP *saml.ServiceProvider,
) (string, error) {
	if logoutRequest == nil {
		return "", fmt.Errorf("logout request payload is missing")
	}

	unsigned := *logoutRequest
	unsigned.Signature = nil

	return buildSignedRedirectSLOURL(unsigned.Element(), unsigned.Destination, samlRedirectRequestParam, relayState, signingSP)
}

// buildSignedRedirectLogoutResponseURL encodes an outbound LogoutResponse for the HTTP-Redirect binding.
func buildSignedRedirectLogoutResponseURL(
	logoutResponse *saml.LogoutResponse,
	relayState string,
	signingSP *saml.ServiceProvider,
) (string, error) {
	if logoutResponse == nil {
		return "", fmt.Errorf("logout response payload is missing")
	}

	unsigned := *logoutResponse
	unsigned.Signature = nil

	return buildSignedRedirectSLOURL(unsigned.Element(), unsigned.Destination, samlRedirectResponseParam, relayState, signingSP)
}

// buildSignedRedirectSLOURL deflates an unsigned SAML message and appends a detached query-string signature.
// The signed octet string is built from the URL-encoded parameters in the order required by
// saml-bindings-2.0-os §3.4.4.1; query parameters already present in the destination are not covered.
func buildSignedRedirectSLOURL(
	message *etree.Element,
	destination string,
	payloadKey string,
	relayState string,
	signingSP *saml.ServiceProvider,
) (string, error) {
	if signingSP == nil {
		return "", fmt.Errorf("SAML redirect signer is missing")
	}

	target, err := parseAbsoluteURL(destination)
	if err != nil {
		return "", err
	}

	deflated, err := deflateSAMLRedirectElement(message)
	if err != nil {
		return "", err
	}

	signedContent := payloadKey + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated))
	if relayState != "" {
		signedContent += "&" + samlRedirectRelayStateParam + "=" + url.QueryEscape(relayState)
	}

	signedContent += "&" + samlRedirectSigAlgParam + "=" + url.QueryEscape(signingSP.SignatureMethod)

	signingContext, err := saml.GetSigningContext(signingSP)
	if err != nil {
		return "", err
	}

	signature, err := signingContext.SignString(signedContent)
	if err != nil {
		return "", err
	}

	query := signedContent + "&" + samlRedirectSignatureParam + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))

	if target.RawQuery != "" {
		target.RawQuery += "&" + query
	} else {
		target.RawQuery = query
	}

	return target.String(), nil
}

// deflateSAMLRedirectElement serializes a SAML message and applies raw DEFLATE as the Redirect binding requires.
func deflateSAMLRedirectElement(message *etree.Element) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("SAML redirect message is missing")
	}

	document := etree.NewDocument()
	document.SetRoot(message)

	var deflated bytes.Buffer

	writer, err := flate.NewWriter(&deflated, flate.BestCompression)
	if err != nil {
		return nil, err
	}

	if _, err = document.WriteTo(writer); err != nil {
		return nil, fmt.Errorf("cannot deflate SAML redirect message: %w", err)
	}

	if err = writer.Close(); err != nil {
		return nil, fmt.Errorf("cannot deflate SAML redirect message: %w", err)
	}

	return deflated.Bytes(), nil
}
