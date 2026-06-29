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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	samlSLOFlateUncompressLimit = 10 * 1024 * 1024
	xmlDSigNamespace            = "http://www.w3.org/2000/09/xmldsig#"
)

type redirectSLOSignatureParts struct {
	SignedContent string
	SigAlgValue   string
	Signature     []byte
	HasSignature  bool
}

type sloInboundSignatureValidation[T any] struct {
	decode         func(slodomain.Binding, string) ([]byte, T, error)
	issuer         func(T) string
	shouldValidate func(slodomain.Binding, string, []byte, bool) (bool, error)
	validate       func(slodomain.Binding, string, []byte, []*x509.Certificate) error
	required       func(string) bool
	messageType    sloMessageType
	label          string
}

func (h *SAMLHandler) validateInboundLogoutRequestSignature(req *http.Request, message *sloInboundMessage) (*saml.LogoutRequest, error) {
	return validateInboundSLOSignature(h, req, message, sloInboundSignatureValidation[*saml.LogoutRequest]{
		decode:         decodeLogoutRequestPayload,
		issuer:         logoutRequestIssuerValue,
		shouldValidate: shouldValidateInboundLogoutRequestSignature,
		validate:       validateLogoutRequestSignatureForBinding,
		required:       h.logoutRequestSignatureRequired,
		messageType:    sloMessageTypeRequest,
		label:          "logout request",
	})
}

func (h *SAMLHandler) validateInboundLogoutResponseSignature(req *http.Request, message *sloInboundMessage) (*saml.LogoutResponse, error) {
	return validateInboundSLOSignature(h, req, message, sloInboundSignatureValidation[*saml.LogoutResponse]{
		decode:         decodeLogoutResponsePayload,
		issuer:         logoutResponseIssuerValue,
		shouldValidate: shouldValidateInboundLogoutResponseSignature,
		validate:       validateLogoutResponseSignatureForBinding,
		required:       h.logoutResponseSignatureRequired,
		messageType:    sloMessageTypeResponse,
		label:          "logout response",
	})
}

// validateInboundSLOSignature executes the shared inbound SLO signature validation flow.
func validateInboundSLOSignature[T any](
	handler *SAMLHandler,
	req *http.Request,
	message *sloInboundMessage,
	validation sloInboundSignatureValidation[T],
) (T, error) {
	var zero T

	if err := validateSLOSignatureHTTPMessage(req, message, validation.messageType, validation.label); err != nil {
		return zero, err
	}

	payloadXML, payload, err := validation.decode(message.Binding, message.Payload)
	if err != nil {
		return zero, err
	}

	issuer := validation.issuer(payload)
	if issuer == "" {
		return zero, fmt.Errorf("%s issuer is missing", validation.label)
	}

	shouldValidate, err := validation.shouldValidate(message.Binding, req.URL.RawQuery, payloadXML, validation.required(issuer))
	if err != nil {
		return zero, err
	}

	if !shouldValidate {
		return payload, nil
	}

	certs, err := handler.resolveLogoutRequestSigningCerts(issuer)
	if err != nil {
		return zero, err
	}

	if err = validation.validate(message.Binding, req.URL.RawQuery, payloadXML, certs); err != nil {
		return zero, err
	}

	return payload, nil
}

// logoutRequestIssuerValue returns the trimmed LogoutRequest issuer.
func logoutRequestIssuerValue(request *saml.LogoutRequest) string {
	if request.Issuer == nil {
		return ""
	}

	return strings.TrimSpace(request.Issuer.Value)
}

// logoutResponseIssuerValue returns the trimmed LogoutResponse issuer.
func logoutResponseIssuerValue(response *saml.LogoutResponse) string {
	if response.Issuer == nil {
		return ""
	}

	return strings.TrimSpace(response.Issuer.Value)
}

// validateSLOSignatureHTTPMessage checks the shared HTTP and message preconditions.
func validateSLOSignatureHTTPMessage(req *http.Request, message *sloInboundMessage, expectedType sloMessageType, label string) error {
	if req == nil {
		return fmt.Errorf("%s is missing HTTP context", label)
	}

	if req.URL == nil {
		return fmt.Errorf("%s URL is missing", label)
	}

	if message == nil {
		return fmt.Errorf("%s payload is missing", label)
	}

	if message.MessageType != expectedType {
		return fmt.Errorf("unsupported message type %q", message.MessageType)
	}

	return nil
}

// logoutRequestSignatureRequired returns the configured LogoutRequest signature policy.
func (h *SAMLHandler) logoutRequestSignatureRequired(issuer string) bool {
	if sp, ok := h.findConfiguredSAMLServiceProvider(issuer); ok {
		return sp.AreLogoutRequestsSigned()
	}

	return true
}

// logoutResponseSignatureRequired returns the configured LogoutResponse signature policy.
func (h *SAMLHandler) logoutResponseSignatureRequired(issuer string) bool {
	if sp, ok := h.findConfiguredSAMLServiceProvider(issuer); ok {
		return sp.AreLogoutResponsesSigned()
	}

	return true
}

// validateLogoutRequestSignatureForBinding validates a LogoutRequest signature for its binding.
func validateLogoutRequestSignatureForBinding(
	binding slodomain.Binding,
	rawQuery string,
	requestXML []byte,
	certs []*x509.Certificate,
) error {
	switch binding {
	case slodomain.SLOBindingRedirect:
		return validateRedirectLogoutRequestSignature(rawQuery, certs)
	case slodomain.SLOBindingPost:
		return validateXMLLogoutRequestSignature(requestXML, certs)
	default:
		return fmt.Errorf("unsupported SLO binding %q", binding)
	}
}

// validateLogoutResponseSignatureForBinding validates a LogoutResponse signature for its binding.
func validateLogoutResponseSignatureForBinding(
	binding slodomain.Binding,
	rawQuery string,
	responseXML []byte,
	certs []*x509.Certificate,
) error {
	switch binding {
	case slodomain.SLOBindingRedirect:
		return validateRedirectLogoutResponseSignature(rawQuery, responseXML, certs)
	case slodomain.SLOBindingPost:
		return validateXMLLogoutResponseSignature(responseXML, certs)
	default:
		return fmt.Errorf("unsupported SLO binding %q", binding)
	}
}

func shouldValidateInboundLogoutRequestSignature(binding slodomain.Binding, rawQuery string, requestXML []byte, required bool) (bool, error) {
	return shouldValidateInboundSAMLRequestSignature(binding, rawQuery, requestXML, required, "SLO")
}

// shouldValidateInboundSAMLRequestSignature decides if a Redirect or POST request signature must be checked.
func shouldValidateInboundSAMLRequestSignature(binding slodomain.Binding, rawQuery string, requestXML []byte, required bool, label string) (bool, error) {
	switch binding {
	case slodomain.SLOBindingRedirect:
		hasSignature, err := redirectSLOHasDetachedSignature(rawQuery)
		if err != nil {
			return false, err
		}

		return required || hasSignature, nil
	case slodomain.SLOBindingPost:
		hasSignature, err := xmlSLOHasSignature(requestXML)
		if err != nil {
			return false, err
		}

		return required || hasSignature, nil
	default:
		return false, fmt.Errorf("unsupported %s binding %q", label, binding)
	}
}

func shouldValidateInboundLogoutResponseSignature(binding slodomain.Binding, rawQuery string, responseXML []byte, required bool) (bool, error) {
	switch binding {
	case slodomain.SLOBindingRedirect:
		hasDetachedSignature, err := redirectSLOHasDetachedSignature(rawQuery)
		if err != nil {
			return false, err
		}

		hasXMLSignature, err := xmlSLOHasSignature(responseXML)
		if err != nil {
			return false, err
		}

		return required || hasDetachedSignature || hasXMLSignature, nil
	case slodomain.SLOBindingPost:
		hasSignature, err := xmlSLOHasSignature(responseXML)
		if err != nil {
			return false, err
		}

		return required || hasSignature, nil
	default:
		return false, fmt.Errorf("unsupported SLO binding %q", binding)
	}
}

// decodeLogoutRequestPayload decodes and validates a SAML LogoutRequest payload.
func decodeLogoutRequestPayload(binding slodomain.Binding, payload string) ([]byte, *saml.LogoutRequest, error) {
	return decodeLogoutPayload[saml.LogoutRequest](binding, payload, "LogoutRequest", decodeLogoutRequestXML)
}

// decodeLogoutResponsePayload decodes and validates a SAML LogoutResponse payload.
func decodeLogoutResponsePayload(binding slodomain.Binding, payload string) ([]byte, *saml.LogoutResponse, error) {
	return decodeLogoutPayload[saml.LogoutResponse](binding, payload, "LogoutResponse", decodeLogoutResponseXML)
}

// decodeLogoutPayload validates XML round-tripping before unmarshalling a typed SLO payload.
func decodeLogoutPayload[T any](
	binding slodomain.Binding,
	payload string,
	messageName string,
	decodeXML func(slodomain.Binding, string) ([]byte, error),
) ([]byte, *T, error) {
	messageXML, err := decodeXML(binding, payload)
	if err != nil {
		return nil, nil, err
	}

	if err = xrv.Validate(bytes.NewReader(messageXML)); err != nil {
		return nil, nil, fmt.Errorf("invalid %s XML: %w", messageName, err)
	}

	var message T

	if err = xml.Unmarshal(messageXML, &message); err != nil {
		return nil, nil, fmt.Errorf("cannot parse %s XML: %w", messageName, err)
	}

	return messageXML, &message, nil
}

func decodeLogoutRequestXML(binding slodomain.Binding, payload string) ([]byte, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, fmt.Errorf("logout request payload is empty")
	}

	rawPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("cannot decode LogoutRequest payload: %w", err)
	}

	switch binding {
	case slodomain.SLOBindingRedirect:
		return inflateSAMLRedirectPayload(rawPayload)
	case slodomain.SLOBindingPost:
		return rawPayload, nil
	default:
		return nil, fmt.Errorf("unsupported SLO binding %q", binding)
	}
}

func decodeLogoutResponseXML(binding slodomain.Binding, payload string) ([]byte, error) {
	return decodeLogoutRequestXML(binding, payload)
}

func inflateSAMLRedirectPayload(rawPayload []byte) ([]byte, error) {
	reader := &sloSaferFlateReader{reader: flate.NewReader(bytes.NewReader(rawPayload))}
	defer func() { _ = reader.Close() }()

	xmlPayload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("cannot inflate LogoutRequest payload: %w", err)
	}

	return xmlPayload, nil
}

func (h *SAMLHandler) resolveLogoutRequestSigningCerts(issuer string) ([]*x509.Certificate, error) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return nil, fmt.Errorf("SAML handler configuration is not available")
	}

	if certs, ok, err := h.resolveMetadataLogoutRequestSigningCerts(issuer); ok || err != nil {
		return certs, err
	}

	if certs, ok, err := h.resolveConfiguredLogoutRequestSigningCerts(issuer); ok || err != nil {
		return certs, err
	}

	return nil, fmt.Errorf("unknown SAML service provider issuer %q", issuer)
}

// resolveMetadataLogoutRequestSigningCerts loads signing certificates through SP metadata.
func (h *SAMLHandler) resolveMetadataLogoutRequestSigningCerts(issuer string) ([]*x509.Certificate, bool, error) {
	if h.idp == nil {
		return nil, false, nil
	}

	serviceProviderMetadata, err := h.GetServiceProvider(nil, issuer)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("failed to load SP metadata for %q: %w", issuer, err)
	}

	certs, err := parseMetadataSigningCertificates(serviceProviderMetadata)
	if err != nil {
		return nil, false, fmt.Errorf("invalid SP signing certificate for %q: %w", issuer, err)
	}

	return certs, len(certs) > 0, nil
}

// resolveConfiguredLogoutRequestSigningCerts loads signing certificates from configured SP entries.
func (h *SAMLHandler) resolveConfiguredLogoutRequestSigningCerts(issuer string) ([]*x509.Certificate, bool, error) {
	samlCfg := h.deps.Cfg.GetIDP().SAML2

	for i := range samlCfg.ServiceProviders {
		sp := &samlCfg.ServiceProviders[i]
		if sp.EntityID != issuer {
			continue
		}

		certStr, err := sp.GetCert()
		if err != nil {
			return nil, false, fmt.Errorf("failed to read SP certificate for %q: %w", issuer, err)
		}

		certs, err := parsePEMCertificates(certStr)
		if err != nil {
			return nil, false, fmt.Errorf("invalid SP signing certificate for %q: %w", issuer, err)
		}

		return certs, true, nil
	}

	return nil, false, nil
}

func parseMetadataSigningCertificates(entityDescriptor *saml.EntityDescriptor) ([]*x509.Certificate, error) {
	if entityDescriptor == nil {
		return nil, nil
	}

	//nolint:prealloc // Number of certificates depends on metadata payload.
	var certs []*x509.Certificate

	for _, ssoDescriptor := range entityDescriptor.SPSSODescriptors {
		for _, keyDescriptor := range ssoDescriptor.KeyDescriptors {
			switch keyDescriptor.Use {
			case "", "signing":
			default:
				continue
			}

			for _, x509Certificate := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
				certificateValue := strings.Join(strings.Fields(x509Certificate.Data), "")
				if certificateValue == "" {
					continue
				}

				certDER, err := base64.StdEncoding.DecodeString(certificateValue)
				if err != nil {
					return nil, fmt.Errorf("failed to decode metadata certificate: %w", err)
				}

				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					return nil, fmt.Errorf("failed to parse metadata x509 certificate: %w", err)
				}

				certs = append(certs, cert)
			}
		}
	}

	return certs, nil
}

func parsePEMCertificates(certPEM string) ([]*x509.Certificate, error) {
	data := []byte(strings.TrimSpace(certPEM))
	if len(data) == 0 {
		return nil, fmt.Errorf("certificate is empty")
	}

	//nolint:prealloc // No known upper bound for certificates.
	var certs []*x509.Certificate

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		data = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificate found")
	}

	return certs, nil
}

func validateRedirectLogoutRequestSignature(rawQuery string, certs []*x509.Certificate) error {
	parts, err := parseRedirectSLOSignatureParts(rawQuery, "SAMLRequest", true)
	if err != nil {
		return err
	}

	return verifyRedirectSLOSignature(parts, certs, "logout request")
}

func validateRedirectLogoutResponseSignature(rawQuery string, responseXML []byte, certs []*x509.Certificate) error {
	parts, err := parseRedirectSLOSignatureParts(rawQuery, "SAMLResponse", false)
	if err != nil {
		return err
	}

	if !parts.HasSignature {
		if err = validateXMLLogoutResponseSignature(responseXML, certs); err != nil {
			return err
		}

		return nil
	}

	return verifyRedirectSLOSignature(parts, certs, "logout response")
}

// parseRedirectSLOSignatureParts extracts and decodes detached redirect signature fields.
func parseRedirectSLOSignatureParts(rawQuery, payloadKey string, signatureRequired bool) (redirectSLOSignatureParts, error) {
	rawPayload, hasPayload, err := rawQueryParameterStrictSLO(rawQuery, payloadKey)
	if err != nil {
		return redirectSLOSignatureParts{}, err
	}

	if !hasPayload || rawPayload == "" {
		return redirectSLOSignatureParts{}, fmt.Errorf("redirect binding signature is malformed: missing %s", payloadKey)
	}

	rawRelayState, hasRelayState, err := rawQueryParameterStrictSLO(rawQuery, "RelayState")
	if err != nil {
		return redirectSLOSignatureParts{}, err
	}

	rawSignature, hasSignature, rawSigAlg, err := redirectSLODetachedSignatureParams(rawQuery)
	if err != nil {
		return redirectSLOSignatureParts{}, err
	}

	if !hasSignature {
		if signatureRequired {
			return redirectSLOSignatureParts{}, fmt.Errorf("redirect binding signature is required")
		}

		return redirectSLOSignatureParts{}, nil
	}

	signedContent := payloadKey + "=" + rawPayload
	if hasRelayState {
		signedContent += "&RelayState=" + rawRelayState
	}

	signedContent += "&SigAlg=" + rawSigAlg

	sigAlgValue, err := url.QueryUnescape(rawSigAlg)
	if err != nil {
		return redirectSLOSignatureParts{}, fmt.Errorf("cannot decode SigAlg: %w", err)
	}

	signature, err := decodeRedirectSLOSignature(rawSignature)
	if err != nil {
		return redirectSLOSignatureParts{}, err
	}

	return redirectSLOSignatureParts{
		SignedContent: signedContent,
		SigAlgValue:   sigAlgValue,
		Signature:     signature,
		HasSignature:  true,
	}, nil
}

// redirectSLODetachedSignatureParams returns the raw Signature and SigAlg values.
func redirectSLODetachedSignatureParams(rawQuery string) (rawSignature string, hasSignature bool, rawSigAlg string, err error) {
	rawSignature, hasSignature, err = rawQueryParameterStrictSLO(rawQuery, "Signature")
	if err != nil {
		return "", false, "", err
	}

	rawSigAlg, hasSigAlg, err := rawQueryParameterStrictSLO(rawQuery, "SigAlg")
	if err != nil {
		return "", false, "", err
	}

	if hasSignature != hasSigAlg {
		return "", false, "", fmt.Errorf("redirect binding signature is malformed: require both Signature and SigAlg")
	}

	return rawSignature, hasSignature, rawSigAlg, nil
}

// decodeRedirectSLOSignature decodes the raw redirect Signature value.
func decodeRedirectSLOSignature(rawSignature string) ([]byte, error) {
	sigB64, err := url.QueryUnescape(rawSignature)
	if err != nil {
		return nil, fmt.Errorf("cannot decode Signature: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("cannot decode Signature base64: %w", err)
	}

	return signature, nil
}

// verifyRedirectSLOSignature verifies decoded detached redirect signature parts.
func verifyRedirectSLOSignature(parts redirectSLOSignatureParts, certs []*x509.Certificate, messageName string) error {
	algorithm, ok := signatureAlgorithmForRedirectSLO(parts.SigAlgValue)
	if !ok {
		return fmt.Errorf("unsupported redirect signature algorithm %q", parts.SigAlgValue)
	}

	var verifyErr error

	for _, cert := range certs {
		if cert == nil {
			continue
		}

		checkErr := cert.CheckSignature(algorithm, []byte(parts.SignedContent), parts.Signature)
		if checkErr == nil {
			return nil
		}

		verifyErr = checkErr
	}

	if verifyErr == nil {
		verifyErr = fmt.Errorf("no usable signing certificate")
	}

	return fmt.Errorf("invalid redirect %s signature: %w", messageName, verifyErr)
}

func redirectSLOHasDetachedSignature(rawQuery string) (bool, error) {
	_, hasSignature, err := rawQueryParameterStrictSLO(rawQuery, "Signature")
	if err != nil {
		return false, err
	}

	_, hasSigAlg, err := rawQueryParameterStrictSLO(rawQuery, "SigAlg")
	if err != nil {
		return false, err
	}

	if hasSignature != hasSigAlg {
		return false, fmt.Errorf("redirect binding signature is malformed: require both Signature and SigAlg")
	}

	return hasSignature, nil
}

// validateXMLLogoutRequestSignature validates an enveloped XML signature on a LogoutRequest.
func validateXMLLogoutRequestSignature(requestXML []byte, certs []*x509.Certificate) error {
	return validateXMLLogoutSignature(requestXML, certs, "LogoutRequest", "logout request")
}

// validateXMLLogoutSignature performs the shared SLO XML signature validation flow.
func validateXMLLogoutSignature(documentXML []byte, certs []*x509.Certificate, messageName string, lowerMessageName string) error {
	root, err := prepareSLOXMLSignatureRoot(documentXML, messageName, lowerMessageName)
	if err != nil {
		return err
	}

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: certs,
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)

	validationContext.IdAttribute = samlXMLIDAttribute
	if saml.Clock != nil {
		validationContext.Clock = saml.Clock
	}

	ctx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return fmt.Errorf("cannot validate %s XML signature: %v", messageName, err)
	}

	ctx, err = ctx.SubContext(root)
	if err != nil {
		return fmt.Errorf("cannot validate %s XML signature: %v", messageName, err)
	}

	root, err = etreeutils.NSDetatch(ctx, root)
	if err != nil {
		return fmt.Errorf("cannot validate %s XML signature: %v", messageName, err)
	}

	if _, err := validationContext.Validate(root); err != nil {
		return fmt.Errorf("cannot validate %s XML signature: %v", messageName, err)
	}

	return nil
}

// prepareSLOXMLSignatureRoot parses XML and strips embedded KeyInfo when needed.
func prepareSLOXMLSignatureRoot(documentXML []byte, messageName string, lowerMessageName string) (*etree.Element, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(documentXML); err != nil {
		return nil, fmt.Errorf("cannot parse %s XML: %w", messageName, err)
	}

	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("%s XML does not have a root element", messageName)
	}

	if signatureMethod := xmlSignatureMethodSLO(root); isWeakSHA1SignatureMethodSLO(signatureMethod) {
		return nil, fmt.Errorf("unsupported XML signature algorithm %q", signatureMethod)
	}

	signatureElement, err := findChildByNamespace(root, xmlDSigNamespace, "Signature")
	if err != nil {
		return nil, fmt.Errorf("cannot inspect %s signature: %w", messageName, err)
	}

	if signatureElement == nil {
		return nil, fmt.Errorf("%s XML signature is required", lowerMessageName)
	}

	removeEmbeddedSLOKeyInfo(signatureElement)

	return root, nil
}

// removeEmbeddedSLOKeyInfo strips KeyInfo when no embedded certificate is present.
func removeEmbeddedSLOKeyInfo(signatureElement *etree.Element) {
	if signatureElementHasX509Cert(signatureElement) {
		return
	}

	if keyInfo := findDirectChildByLocalTag(signatureElement, "KeyInfo"); keyInfo != nil {
		signatureElement.RemoveChild(keyInfo)
	}
}

func xmlSLOHasSignature(document []byte) (bool, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(document); err != nil {
		return false, fmt.Errorf("cannot parse SLO XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return false, fmt.Errorf("SLO XML does not have a root element")
	}

	signatureElement, err := findChildByNamespace(root, xmlDSigNamespace, "Signature")
	if err != nil {
		return false, err
	}

	return signatureElement != nil, nil
}

// validateXMLLogoutResponseSignature validates an enveloped XML signature on a LogoutResponse.
func validateXMLLogoutResponseSignature(responseXML []byte, certs []*x509.Certificate) error {
	return validateXMLLogoutSignature(responseXML, certs, "LogoutResponse", "logout response")
}

func signatureAlgorithmForRedirectSLO(identifier string) (x509.SignatureAlgorithm, bool) {
	switch identifier {
	case dsig.RSASHA256SignatureMethod:
		return x509.SHA256WithRSA, true
	case dsig.RSASHA384SignatureMethod:
		return x509.SHA384WithRSA, true
	case dsig.RSASHA512SignatureMethod:
		return x509.SHA512WithRSA, true
	case dsig.ECDSASHA256SignatureMethod:
		return x509.ECDSAWithSHA256, true
	case dsig.ECDSASHA384SignatureMethod:
		return x509.ECDSAWithSHA384, true
	case dsig.ECDSASHA512SignatureMethod:
		return x509.ECDSAWithSHA512, true
	default:
		return x509.UnknownSignatureAlgorithm, false
	}
}

func xmlSignatureMethodSLO(root *etree.Element) string {
	if root == nil {
		return ""
	}

	for _, child := range root.FindElements(".//*") {
		if localTagName(child.Tag) != "SignatureMethod" {
			continue
		}

		return child.SelectAttrValue("Algorithm", "")
	}

	return ""
}

func isWeakSHA1SignatureMethodSLO(signatureMethod string) bool {
	switch signatureMethod {
	case dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod:
		return true
	default:
		return false
	}
}

func rawQueryParameterStrictSLO(rawQuery, key string) (string, bool, error) {
	found := false
	value := ""

	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			continue
		}

		if part == key {
			if found {
				return "", false, fmt.Errorf("redirect binding query contains duplicate parameter %q", key)
			}

			found = true
			value = ""

			continue
		}

		if strings.HasPrefix(part, key+"=") {
			if found {
				return "", false, fmt.Errorf("redirect binding query contains duplicate parameter %q", key)
			}

			found = true
			value = strings.TrimPrefix(part, key+"=")
		}
	}

	return value, found, nil
}

func findChildByNamespace(parent *etree.Element, childNamespace string, childTag string) (*etree.Element, error) {
	children, err := findChildrenByNamespace(parent, childNamespace, childTag)
	if err != nil {
		return nil, err
	}

	switch len(children) {
	case 0:
		return nil, nil
	case 1:
		return children[0], nil
	default:
		return nil, fmt.Errorf("expected at most one %s:%s element", childNamespace, childTag)
	}
}

func findChildrenByNamespace(parent *etree.Element, childNamespace string, childTag string) ([]*etree.Element, error) {
	//nolint:prealloc // Number of matching elements is unknown.
	var children []*etree.Element

	for _, child := range parent.ChildElements() {
		if localTagName(child.Tag) != childTag {
			continue
		}

		ctx, err := etreeutils.NSBuildParentContext(child)
		if err != nil {
			return nil, err
		}

		ctx, err = ctx.SubContext(child)
		if err != nil {
			return nil, err
		}

		namespace, err := ctx.LookupPrefix(child.Space)
		if err != nil {
			return nil, fmt.Errorf("[%s]:%s cannot find prefix %s: %v", childNamespace, childTag, child.Space, err)
		}

		if namespace != childNamespace {
			continue
		}

		children = append(children, child)
	}

	return children, nil
}

func signatureElementHasX509Cert(signatureElement *etree.Element) bool {
	if signatureElement == nil {
		return false
	}

	for _, child := range signatureElement.FindElements(".//*") {
		if localTagName(child.Tag) == "X509Certificate" {
			return true
		}
	}

	return false
}

func findDirectChildByLocalTag(parent *etree.Element, localTag string) *etree.Element {
	if parent == nil {
		return nil
	}

	for _, child := range parent.ChildElements() {
		if localTagName(child.Tag) == localTag {
			return child
		}
	}

	return nil
}

func localTagName(tag string) string {
	if idx := strings.LastIndex(tag, ":"); idx >= 0 && idx < len(tag)-1 {
		return tag[idx+1:]
	}

	return tag
}

type sloSaferFlateReader struct {
	reader io.ReadCloser
	count  int
}

func (r *sloSaferFlateReader) Read(p []byte) (int, error) {
	if r.count+len(p) > samlSLOFlateUncompressLimit {
		return 0, fmt.Errorf("flate: uncompress limit exceeded (%d bytes)", samlSLOFlateUncompressLimit)
	}

	n, err := r.reader.Read(p)
	r.count += n

	return n, err
}

func (r *sloSaferFlateReader) Close() error {
	return r.reader.Close()
}
