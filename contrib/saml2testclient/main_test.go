package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestBuildLogoutInitiationRedirect(t *testing.T) {
	t.Parallel()

	serviceProvider := newTestServiceProvider(t)

	testCases := []struct {
		name          string
		signRequest   bool
		wantSignature bool
	}{
		{
			name:        "unsigned redirect request",
			signRequest: false,
		},
		{
			name:          "signed redirect request",
			signRequest:   true,
			wantSignature: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			initiation, err := buildLogoutInitiation(
				serviceProvider,
				saml.HTTPRedirectBinding,
				"alice@example.com",
				"session-123",
				"relay-state",
				tc.signRequest,
			)
			if err != nil {
				t.Fatalf("buildLogoutInitiation failed: %v", err)
			}

			assertRedirectLogoutInitiation(t, initiation, tc.wantSignature)
		})
	}
}

func newTestServiceProvider(t *testing.T) *saml.ServiceProvider {
	t.Helper()

	privateKey, certificate := mustCreateServiceProviderCertificate(t)

	return &saml.ServiceProvider{
		Key:             privateKey,
		Certificate:     certificate,
		MetadataURL:     mustParseURL(t, "https://sp.example.com/saml/metadata"),
		AcsURL:          mustParseURL(t, "https://sp.example.com/saml/acs"),
		SloURL:          mustParseURL(t, "https://sp.example.com/saml/slo"),
		IDPMetadata:     newTestIDPMetadata(),
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}
}

func assertRedirectLogoutInitiation(t *testing.T, initiation *logoutInitiation, wantSignature bool) {
	t.Helper()

	if initiation.Binding != saml.HTTPRedirectBinding {
		t.Fatalf("unexpected binding %q", initiation.Binding)
	}

	if initiation.RedirectURL == nil {
		t.Fatal("expected redirect URL")
	}

	query := initiation.RedirectURL.Query()
	if query.Get("SAMLRequest") == "" {
		t.Fatal("expected SAMLRequest parameter")
	}

	if query.Get("RelayState") != "relay-state" {
		t.Fatalf("unexpected RelayState %q", query.Get("RelayState"))
	}

	assertSignatureState(t, query, wantSignature)

	logoutRequest := decodeRedirectLogoutRequest(t, query.Get("SAMLRequest"))
	if logoutRequest.NameID == nil || logoutRequest.NameID.Value != "alice@example.com" {
		t.Fatal("expected NameID in LogoutRequest")
	}

	if logoutRequest.SessionIndex == nil || logoutRequest.SessionIndex.Value != "session-123" {
		t.Fatal("expected SessionIndex in LogoutRequest")
	}
}

func assertSignatureState(t *testing.T, query url.Values, wantSignature bool) {
	t.Helper()

	if wantSignature {
		if query.Get("Signature") == "" {
			t.Fatal("expected Signature parameter")
		}

		if query.Get("SigAlg") == "" {
			t.Fatal("expected SigAlg parameter")
		}

		return
	}

	if query.Get("Signature") != "" {
		t.Fatal("did not expect Signature parameter")
	}

	if query.Get("SigAlg") != "" {
		t.Fatal("did not expect SigAlg parameter")
	}
}

func mustCreateServiceProviderCertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "sp.example.com",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return privateKey, certificate
}

func mustParseURL(t *testing.T, rawURL string) url.URL {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", rawURL, err)
	}

	return *parsedURL
}

func newTestIDPMetadata() *saml.EntityDescriptor {
	return &saml.EntityDescriptor{
		EntityID: "https://auth.example.com/saml/metadata",
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					},
					SingleLogoutServices: []saml.Endpoint{
						{
							Binding:  saml.HTTPRedirectBinding,
							Location: "https://auth.example.com/saml/slo",
						},
						{
							Binding:  saml.HTTPPostBinding,
							Location: "https://auth.example.com/saml/slo",
						},
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: "https://auth.example.com/saml/sso",
					},
				},
			},
		},
	}
}

func decodeRedirectLogoutRequest(t *testing.T, payload string) *saml.LogoutRequest {
	t.Helper()

	rawPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("failed to decode SAMLRequest payload: %v", err)
	}

	reader := flate.NewReader(bytes.NewReader(rawPayload))
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			t.Fatalf("failed to close flate reader: %v", closeErr)
		}
	}()

	xmlPayload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to inflate LogoutRequest payload: %v", err)
	}

	var logoutRequest saml.LogoutRequest

	if err = xml.Unmarshal(xmlPayload, &logoutRequest); err != nil {
		t.Fatalf("failed to unmarshal LogoutRequest XML: %v", err)
	}

	return &logoutRequest
}
