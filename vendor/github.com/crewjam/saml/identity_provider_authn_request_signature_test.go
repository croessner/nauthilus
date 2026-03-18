package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type staticSPProvider struct {
	descriptors map[string]*EntityDescriptor
}

func (s staticSPProvider) GetServiceProvider(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
	if descriptor, ok := s.descriptors[serviceProviderID]; ok {
		return descriptor, nil
	}

	return nil, os.ErrNotExist
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", rawURL, err)
	}

	return parsedURL
}

func mustCertificate(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return privateKey, certificate
}

func newTestIdentityProvider(t *testing.T) *IdentityProvider {
	t.Helper()

	idpKey, idpCert := mustCertificate(t, "idp.example.com")

	return &IdentityProvider{
		Key:             idpKey,
		Certificate:     idpCert,
		MetadataURL:     *mustParseURL(t, "https://idp.example.com/saml/metadata"),
		SSOURL:          *mustParseURL(t, "https://idp.example.com/saml/sso"),
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}
}

func newTestServiceProvider(t *testing.T, idpMetadata *EntityDescriptor, signatureMethod string) *ServiceProvider {
	t.Helper()

	spKey, spCert := mustCertificate(t, "sp.example.com")

	return &ServiceProvider{
		Key:             spKey,
		Certificate:     spCert,
		MetadataURL:     *mustParseURL(t, "https://sp.example.com/saml/metadata"),
		EntityID:        "https://sp.example.com/saml/metadata",
		AcsURL:          *mustParseURL(t, "https://sp.example.com/saml/acs"),
		IDPMetadata:     idpMetadata,
		SignatureMethod: signatureMethod,
	}
}

func TestIdpAuthnRequestValidateRedirectSignedRequest(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), dsig.RSASHA256SignatureMethod)

	spMetadata := sp.Metadata()
	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	redirectURL, err := sp.MakeRedirectAuthenticationRequest("relay-state")
	if err != nil {
		t.Fatalf("failed to create redirect authn request: %v", err)
	}

	httpRequest := httptest.NewRequest(http.MethodGet, redirectURL.String(), nil)
	authnRequest, err := NewIdpAuthnRequest(idp, httpRequest)
	if err != nil {
		t.Fatalf("failed to parse idp authn request: %v", err)
	}

	if err := authnRequest.Validate(); err != nil {
		t.Fatalf("expected signed redirect authn request to validate, got: %v", err)
	}
}

func TestIdpAuthnRequestValidateRedirectTamperedSignatureFails(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), dsig.RSASHA256SignatureMethod)

	spMetadata := sp.Metadata()
	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	redirectURL, err := sp.MakeRedirectAuthenticationRequest("relay-state")
	if err != nil {
		t.Fatalf("failed to create redirect authn request: %v", err)
	}

	redirectURL.RawQuery = strings.Replace(redirectURL.RawQuery, "RelayState=relay-state", "RelayState=tampered", 1)

	httpRequest := httptest.NewRequest(http.MethodGet, redirectURL.String(), nil)
	authnRequest, err := NewIdpAuthnRequest(idp, httpRequest)
	if err != nil {
		t.Fatalf("failed to parse idp authn request: %v", err)
	}

	err = authnRequest.Validate()
	if err == nil {
		t.Fatal("expected tampered redirect authn request to fail signature validation")
	}
	if !strings.Contains(err.Error(), "invalid redirect authn request signature") {
		t.Fatalf("expected redirect signature error, got: %v", err)
	}
}

func TestIdpAuthnRequestValidateRedirectDuplicateSignatureParameterFails(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), dsig.RSASHA256SignatureMethod)

	spMetadata := sp.Metadata()
	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	redirectURL, err := sp.MakeRedirectAuthenticationRequest("relay-state")
	if err != nil {
		t.Fatalf("failed to create redirect authn request: %v", err)
	}

	redirectURL.RawQuery += "&Signature=AAAA"

	httpRequest := httptest.NewRequest(http.MethodGet, redirectURL.String(), nil)
	authnRequest, err := NewIdpAuthnRequest(idp, httpRequest)
	if err != nil {
		t.Fatalf("failed to parse idp authn request: %v", err)
	}

	err = authnRequest.Validate()
	if err == nil {
		t.Fatal("expected duplicate Signature parameter to fail validation")
	}
	if !strings.Contains(err.Error(), "duplicate parameter") {
		t.Fatalf("expected duplicate parameter error, got: %v", err)
	}
}

func TestIdpAuthnRequestValidateRedirectSHA1Rejected(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), dsig.RSASHA1SignatureMethod)

	spMetadata := sp.Metadata()
	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	redirectURL, err := sp.MakeRedirectAuthenticationRequest("relay-state")
	if err != nil {
		t.Fatalf("failed to create redirect authn request: %v", err)
	}

	httpRequest := httptest.NewRequest(http.MethodGet, redirectURL.String(), nil)
	authnRequest, err := NewIdpAuthnRequest(idp, httpRequest)
	if err != nil {
		t.Fatalf("failed to parse idp authn request: %v", err)
	}

	err = authnRequest.Validate()
	if err == nil {
		t.Fatal("expected SHA-1 redirect signature to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported redirect signature algorithm") {
		t.Fatalf("expected SHA-1 rejection error, got: %v", err)
	}
}

func TestIdpAuthnRequestValidateRedirectUnsignedButRequiredFails(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), "")

	spMetadata := sp.Metadata()
	requireSigned := true
	spMetadata.SPSSODescriptors[0].AuthnRequestsSigned = &requireSigned

	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	redirectURL, err := sp.MakeRedirectAuthenticationRequest("relay-state")
	if err != nil {
		t.Fatalf("failed to create redirect authn request: %v", err)
	}

	httpRequest := httptest.NewRequest(http.MethodGet, redirectURL.String(), nil)
	authnRequest, err := NewIdpAuthnRequest(idp, httpRequest)
	if err != nil {
		t.Fatalf("failed to parse idp authn request: %v", err)
	}

	err = authnRequest.Validate()
	if err == nil {
		t.Fatal("expected unsigned redirect authn request to fail when signatures are required")
	}
	if !strings.Contains(err.Error(), "signature required") {
		t.Fatalf("expected signature required error, got: %v", err)
	}
}

func TestIdpAuthnRequestValidatePostSignedRequest(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), dsig.RSASHA256SignatureMethod)

	spMetadata := sp.Metadata()
	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	postRequest, err := sp.MakeAuthenticationRequest(
		sp.GetSSOBindingLocation(HTTPPostBinding),
		HTTPPostBinding,
		HTTPPostBinding,
	)
	if err != nil {
		t.Fatalf("failed to create post authn request: %v", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(postRequest.Element())
	postRequestXML, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("failed to serialize post authn request: %v", err)
	}

	formBody := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(postRequestXML))
	httpRequest := httptest.NewRequest(http.MethodPost, idp.SSOURL.String(), strings.NewReader(formBody))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	authnRequest, err := NewIdpAuthnRequest(idp, httpRequest)
	if err != nil {
		t.Fatalf("failed to parse idp authn request: %v", err)
	}

	if err := authnRequest.Validate(); err != nil {
		t.Fatalf("expected signed post authn request to validate, got: %v", err)
	}
}

func TestIdpAuthnRequestValidatePostSHA1Rejected(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), dsig.RSASHA1SignatureMethod)

	spMetadata := sp.Metadata()
	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	postRequest, err := sp.MakeAuthenticationRequest(
		sp.GetSSOBindingLocation(HTTPPostBinding),
		HTTPPostBinding,
		HTTPPostBinding,
	)
	if err != nil {
		t.Fatalf("failed to create post authn request: %v", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(postRequest.Element())
	postRequestXML, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("failed to serialize post authn request: %v", err)
	}

	formBody := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(postRequestXML))
	httpRequest := httptest.NewRequest(http.MethodPost, idp.SSOURL.String(), strings.NewReader(formBody))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	authnRequest, err := NewIdpAuthnRequest(idp, httpRequest)
	if err != nil {
		t.Fatalf("failed to parse idp authn request: %v", err)
	}

	err = authnRequest.Validate()
	if err == nil {
		t.Fatal("expected SHA-1 XML signature to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported XML signature algorithm") {
		t.Fatalf("expected SHA-1 rejection error, got: %v", err)
	}
}

func TestIdpAuthnRequestValidateReplayRequestIDFails(t *testing.T) {
	idp := newTestIdentityProvider(t)
	sp := newTestServiceProvider(t, idp.Metadata(), dsig.RSASHA256SignatureMethod)

	spMetadata := sp.Metadata()
	idp.ServiceProviderProvider = staticSPProvider{
		descriptors: map[string]*EntityDescriptor{
			spMetadata.EntityID: spMetadata,
		},
	}

	redirectURL, err := sp.MakeRedirectAuthenticationRequest("relay-state")
	if err != nil {
		t.Fatalf("failed to create redirect authn request: %v", err)
	}

	httpRequest1 := httptest.NewRequest(http.MethodGet, redirectURL.String(), nil)
	authnRequest1, err := NewIdpAuthnRequest(idp, httpRequest1)
	if err != nil {
		t.Fatalf("failed to parse first idp authn request: %v", err)
	}
	if err := authnRequest1.Validate(); err != nil {
		t.Fatalf("expected first request to validate, got: %v", err)
	}

	httpRequest2 := httptest.NewRequest(http.MethodGet, redirectURL.String(), nil)
	authnRequest2, err := NewIdpAuthnRequest(idp, httpRequest2)
	if err != nil {
		t.Fatalf("failed to parse second idp authn request: %v", err)
	}
	err = authnRequest2.Validate()
	if err == nil {
		t.Fatal("expected replayed AuthnRequest ID to fail")
	}
	if !strings.Contains(err.Error(), "replay detected") {
		t.Fatalf("expected replay detection error, got: %v", err)
	}
}
