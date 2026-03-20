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
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	samlSLOFlateUncompressLimit = 10 * 1024 * 1024
	xmlDSigNamespace            = "http://www.w3.org/2000/09/xmldsig#"
)

func (h *SAMLHandler) validateInboundLogoutRequestSignature(req *http.Request, message *sloInboundMessage) (*saml.LogoutRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("logout request is missing HTTP context")
	}

	if req.URL == nil {
		return nil, fmt.Errorf("logout request URL is missing")
	}

	if message == nil {
		return nil, fmt.Errorf("logout request payload is missing")
	}

	if message.MessageType != sloMessageTypeRequest {
		return nil, fmt.Errorf("unsupported message type %q", message.MessageType)
	}

	requestXML, logoutRequest, err := decodeLogoutRequestPayload(message.Binding, message.Payload)
	if err != nil {
		return nil, err
	}

	issuer := ""
	if logoutRequest.Issuer != nil {
		issuer = strings.TrimSpace(logoutRequest.Issuer.Value)
	}

	if issuer == "" {
		return nil, fmt.Errorf("logout request issuer is missing")
	}

	certs, err := h.resolveLogoutRequestSigningCerts(issuer)
	if err != nil {
		return nil, err
	}

	switch message.Binding {
	case slodomain.SLOBindingRedirect:
		if err := validateRedirectLogoutRequestSignature(req.URL.RawQuery, certs); err != nil {
			return nil, err
		}
	case slodomain.SLOBindingPost:
		if err := validateXMLLogoutRequestSignature(requestXML, certs); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported SLO binding %q", message.Binding)
	}

	return logoutRequest, nil
}

func (h *SAMLHandler) validateInboundLogoutResponseSignature(req *http.Request, message *sloInboundMessage) (*saml.LogoutResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("logout response is missing HTTP context")
	}

	if req.URL == nil {
		return nil, fmt.Errorf("logout response URL is missing")
	}

	if message == nil {
		return nil, fmt.Errorf("logout response payload is missing")
	}

	if message.MessageType != sloMessageTypeResponse {
		return nil, fmt.Errorf("unsupported message type %q", message.MessageType)
	}

	responseXML, logoutResponse, err := decodeLogoutResponsePayload(message.Binding, message.Payload)
	if err != nil {
		return nil, err
	}

	issuer := ""
	if logoutResponse.Issuer != nil {
		issuer = strings.TrimSpace(logoutResponse.Issuer.Value)
	}

	if issuer == "" {
		return nil, fmt.Errorf("logout response issuer is missing")
	}

	certs, err := h.resolveLogoutRequestSigningCerts(issuer)
	if err != nil {
		return nil, err
	}

	switch message.Binding {
	case slodomain.SLOBindingRedirect:
		if err = validateRedirectLogoutResponseSignature(req.URL.RawQuery, responseXML, certs); err != nil {
			return nil, err
		}
	case slodomain.SLOBindingPost:
		if err = validateXMLLogoutResponseSignature(responseXML, certs); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported SLO binding %q", message.Binding)
	}

	return logoutResponse, nil
}

func decodeLogoutRequestPayload(binding slodomain.SLOBinding, payload string) ([]byte, *saml.LogoutRequest, error) {
	requestXML, err := decodeLogoutRequestXML(binding, payload)
	if err != nil {
		return nil, nil, err
	}

	if err := xrv.Validate(bytes.NewReader(requestXML)); err != nil {
		return nil, nil, fmt.Errorf("invalid LogoutRequest XML: %w", err)
	}

	var logoutRequest saml.LogoutRequest

	if err := xml.Unmarshal(requestXML, &logoutRequest); err != nil {
		return nil, nil, fmt.Errorf("cannot parse LogoutRequest XML: %w", err)
	}

	return requestXML, &logoutRequest, nil
}

func decodeLogoutResponsePayload(binding slodomain.SLOBinding, payload string) ([]byte, *saml.LogoutResponse, error) {
	responseXML, err := decodeLogoutResponseXML(binding, payload)
	if err != nil {
		return nil, nil, err
	}

	if err = xrv.Validate(bytes.NewReader(responseXML)); err != nil {
		return nil, nil, fmt.Errorf("invalid LogoutResponse XML: %w", err)
	}

	var logoutResponse saml.LogoutResponse

	if err = xml.Unmarshal(responseXML, &logoutResponse); err != nil {
		return nil, nil, fmt.Errorf("cannot parse LogoutResponse XML: %w", err)
	}

	return responseXML, &logoutResponse, nil
}

func decodeLogoutRequestXML(binding slodomain.SLOBinding, payload string) ([]byte, error) {
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

func decodeLogoutResponseXML(binding slodomain.SLOBinding, payload string) ([]byte, error) {
	return decodeLogoutRequestXML(binding, payload)
}

func inflateSAMLRedirectPayload(rawPayload []byte) ([]byte, error) {
	reader := &sloSaferFlateReader{reader: flate.NewReader(bytes.NewReader(rawPayload))}
	defer reader.Close()

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

	if h.idp != nil {
		serviceProviderMetadata, err := h.GetServiceProvider(nil, issuer)
		if err == nil {
			certs, err := parseMetadataSigningCertificates(serviceProviderMetadata)
			if err != nil {
				return nil, fmt.Errorf("invalid SP signing certificate for %q: %w", issuer, err)
			}

			if len(certs) > 0 {
				return certs, nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to load SP metadata for %q: %w", issuer, err)
		}
	}

	samlCfg := h.deps.Cfg.GetIdP().SAML2

	for i := range samlCfg.ServiceProviders {
		sp := &samlCfg.ServiceProviders[i]
		if sp.EntityID != issuer {
			continue
		}

		certStr, err := sp.GetCert()
		if err != nil {
			return nil, fmt.Errorf("failed to read SP certificate for %q: %w", issuer, err)
		}

		certs, err := parsePEMCertificates(certStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SP signing certificate for %q: %w", issuer, err)
		}

		return certs, nil
	}

	return nil, fmt.Errorf("unknown SAML service provider issuer %q", issuer)
}

func parseMetadataSigningCertificates(entityDescriptor *saml.EntityDescriptor) ([]*x509.Certificate, error) {
	if entityDescriptor == nil {
		return nil, nil
	}

	//nolint:prealloc // Number of certificates depends on metadata payload.
	var certs []*x509.Certificate

	for _, ssoDescriptor := range entityDescriptor.SPSSODescriptors {
		for _, keyDescriptor := range ssoDescriptor.RoleDescriptor.KeyDescriptors {
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
	rawSAMLRequest, hasSAMLRequest, err := rawQueryParameterStrictSLO(rawQuery, "SAMLRequest")
	if err != nil {
		return err
	}

	if !hasSAMLRequest || rawSAMLRequest == "" {
		return fmt.Errorf("redirect binding signature is malformed: missing SAMLRequest")
	}

	rawRelayState, hasRelayState, err := rawQueryParameterStrictSLO(rawQuery, "RelayState")
	if err != nil {
		return err
	}

	rawSignature, hasSignature, err := rawQueryParameterStrictSLO(rawQuery, "Signature")
	if err != nil {
		return err
	}

	rawSigAlg, hasSigAlg, err := rawQueryParameterStrictSLO(rawQuery, "SigAlg")
	if err != nil {
		return err
	}

	if hasSignature != hasSigAlg {
		return fmt.Errorf("redirect binding signature is malformed: require both Signature and SigAlg")
	}

	if !hasSignature {
		return fmt.Errorf("redirect binding signature is required")
	}

	signedContent := "SAMLRequest=" + rawSAMLRequest
	if hasRelayState {
		signedContent += "&RelayState=" + rawRelayState
	}
	signedContent += "&SigAlg=" + rawSigAlg

	sigAlgValue, err := url.QueryUnescape(rawSigAlg)
	if err != nil {
		return fmt.Errorf("cannot decode SigAlg: %w", err)
	}

	sigB64, err := url.QueryUnescape(rawSignature)
	if err != nil {
		return fmt.Errorf("cannot decode Signature: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("cannot decode Signature base64: %w", err)
	}

	algorithm, ok := signatureAlgorithmForRedirectSLO(sigAlgValue)
	if !ok {
		return fmt.Errorf("unsupported redirect signature algorithm %q", sigAlgValue)
	}

	var verifyErr error

	for _, cert := range certs {
		if cert == nil {
			continue
		}

		if err := cert.CheckSignature(algorithm, []byte(signedContent), signature); err == nil {
			return nil
		} else {
			verifyErr = err
		}
	}

	if verifyErr == nil {
		verifyErr = fmt.Errorf("no usable signing certificate")
	}

	return fmt.Errorf("invalid redirect logout request signature: %w", verifyErr)
}

func validateRedirectLogoutResponseSignature(rawQuery string, responseXML []byte, certs []*x509.Certificate) error {
	rawSAMLResponse, hasSAMLResponse, err := rawQueryParameterStrictSLO(rawQuery, "SAMLResponse")
	if err != nil {
		return err
	}

	if !hasSAMLResponse || rawSAMLResponse == "" {
		return fmt.Errorf("redirect binding signature is malformed: missing SAMLResponse")
	}

	rawRelayState, hasRelayState, err := rawQueryParameterStrictSLO(rawQuery, "RelayState")
	if err != nil {
		return err
	}

	rawSignature, hasSignature, err := rawQueryParameterStrictSLO(rawQuery, "Signature")
	if err != nil {
		return err
	}

	rawSigAlg, hasSigAlg, err := rawQueryParameterStrictSLO(rawQuery, "SigAlg")
	if err != nil {
		return err
	}

	if hasSignature != hasSigAlg {
		return fmt.Errorf("redirect binding signature is malformed: require both Signature and SigAlg")
	}

	if !hasSignature {
		if err = validateXMLLogoutResponseSignature(responseXML, certs); err != nil {
			return err
		}

		return nil
	}

	signedContent := "SAMLResponse=" + rawSAMLResponse
	if hasRelayState {
		signedContent += "&RelayState=" + rawRelayState
	}
	signedContent += "&SigAlg=" + rawSigAlg

	sigAlgValue, err := url.QueryUnescape(rawSigAlg)
	if err != nil {
		return fmt.Errorf("cannot decode SigAlg: %w", err)
	}

	sigB64, err := url.QueryUnescape(rawSignature)
	if err != nil {
		return fmt.Errorf("cannot decode Signature: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("cannot decode Signature base64: %w", err)
	}

	algorithm, ok := signatureAlgorithmForRedirectSLO(sigAlgValue)
	if !ok {
		return fmt.Errorf("unsupported redirect signature algorithm %q", sigAlgValue)
	}

	var verifyErr error

	for _, cert := range certs {
		if cert == nil {
			continue
		}

		if err = cert.CheckSignature(algorithm, []byte(signedContent), signature); err == nil {
			return nil
		}

		verifyErr = err
	}

	if verifyErr == nil {
		verifyErr = fmt.Errorf("no usable signing certificate")
	}

	return fmt.Errorf("invalid redirect logout response signature: %w", verifyErr)
}

func validateXMLLogoutRequestSignature(requestXML []byte, certs []*x509.Certificate) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(requestXML); err != nil {
		return fmt.Errorf("cannot parse LogoutRequest XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return fmt.Errorf("LogoutRequest XML does not have a root element")
	}

	signatureMethod := xmlSignatureMethodSLO(root)
	if isWeakSHA1SignatureMethodSLO(signatureMethod) {
		return fmt.Errorf("unsupported XML signature algorithm %q", signatureMethod)
	}

	signatureElement, err := findChildByNamespace(root, xmlDSigNamespace, "Signature")
	if err != nil {
		return fmt.Errorf("cannot inspect LogoutRequest signature: %w", err)
	}

	if signatureElement == nil {
		return fmt.Errorf("logout request XML signature is required")
	}

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: certs,
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	if saml.Clock != nil {
		validationContext.Clock = saml.Clock
	}

	if !signatureElementHasX509Cert(signatureElement) {
		if keyInfo := findDirectChildByLocalTag(signatureElement, "KeyInfo"); keyInfo != nil {
			signatureElement.RemoveChild(keyInfo)
		}
	}

	ctx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return fmt.Errorf("cannot validate LogoutRequest XML signature: %v", err)
	}

	ctx, err = ctx.SubContext(root)
	if err != nil {
		return fmt.Errorf("cannot validate LogoutRequest XML signature: %v", err)
	}

	root, err = etreeutils.NSDetatch(ctx, root)
	if err != nil {
		return fmt.Errorf("cannot validate LogoutRequest XML signature: %v", err)
	}

	if _, err := validationContext.Validate(root); err != nil {
		return fmt.Errorf("cannot validate LogoutRequest XML signature: %v", err)
	}

	return nil
}

func validateXMLLogoutResponseSignature(responseXML []byte, certs []*x509.Certificate) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(responseXML); err != nil {
		return fmt.Errorf("cannot parse LogoutResponse XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return fmt.Errorf("LogoutResponse XML does not have a root element")
	}

	signatureMethod := xmlSignatureMethodSLO(root)
	if isWeakSHA1SignatureMethodSLO(signatureMethod) {
		return fmt.Errorf("unsupported XML signature algorithm %q", signatureMethod)
	}

	signatureElement, err := findChildByNamespace(root, xmlDSigNamespace, "Signature")
	if err != nil {
		return fmt.Errorf("cannot inspect LogoutResponse signature: %w", err)
	}

	if signatureElement == nil {
		return fmt.Errorf("logout response XML signature is required")
	}

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: certs,
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	if saml.Clock != nil {
		validationContext.Clock = saml.Clock
	}

	if !signatureElementHasX509Cert(signatureElement) {
		if keyInfo := findDirectChildByLocalTag(signatureElement, "KeyInfo"); keyInfo != nil {
			signatureElement.RemoveChild(keyInfo)
		}
	}

	ctx, err := etreeutils.NSBuildParentContext(root)
	if err != nil {
		return fmt.Errorf("cannot validate LogoutResponse XML signature: %v", err)
	}

	ctx, err = ctx.SubContext(root)
	if err != nil {
		return fmt.Errorf("cannot validate LogoutResponse XML signature: %v", err)
	}

	root, err = etreeutils.NSDetatch(ctx, root)
	if err != nil {
		return fmt.Errorf("cannot validate LogoutResponse XML signature: %v", err)
	}

	if _, err = validationContext.Validate(root); err != nil {
		return fmt.Errorf("cannot validate LogoutResponse XML signature: %v", err)
	}

	return nil
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
