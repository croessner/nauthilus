// Copyright (C) 2025 Christian Rößner
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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // used in tests to assert SHA-1 rejection paths.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
)

const (
	samlSensitiveTOTPField     = "ldap_totp_secret"
	samlSensitiveRecoveryField = "ldap_totp_recovery"
	samlSensitiveTOTPValue     = "fake-saml-totp-seed-not-for-output"
	samlSensitiveRecoveryValue = "fake-saml-recovery-code-not-for-output"
)

type mockSAMLCfg struct {
	config.File
	entityID              string
	certificate           string
	key                   string
	redisPrefix           string
	sps                   []config.SAML2ServiceProvider
	sloEnabled            *bool
	sloFrontChannel       *bool
	sloBackChannelEnabled *bool
	sloRequestTimeout     time.Duration
	sloMaxParticipants    int
	sloBackChannelRetries int
}

func (m *mockSAMLCfg) GetIDP() *config.IDPSection {
	return &config.IDPSection{
		OIDC: config.OIDCConfig{
			Issuer: "https://auth.example.com",
		},
		SAML2: config.SAML2Config{
			EntityID:         m.entityID,
			Cert:             m.certificate,
			Key:              m.key,
			ServiceProviders: m.sps,
			SLO: config.SAML2SLOConfig{
				Enabled:               m.sloEnabled,
				FrontChannelEnabled:   m.sloFrontChannel,
				BackChannelEnabled:    m.sloBackChannelEnabled,
				RequestTimeout:        m.sloRequestTimeout,
				MaxParticipants:       m.sloMaxParticipants,
				BackChannelMaxRetries: m.sloBackChannelRetries,
			},
		},
	}
}

func (m *mockSAMLCfg) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Redis: config.Redis{
			Prefix: m.redisPrefix,
		},
	}
}

func (m *mockSAMLCfg) GetLDAP() *config.LDAPSection {
	return &config.LDAPSection{}
}

func TestSAMLUnrestrictedAttributesSuppressSensitive(t *testing.T) {
	session := &saml.Session{}
	user := newSAMLAttributeUser(map[string][]any{
		"email":                    {"alice@example.com"},
		samlSensitiveTOTPField:     {samlSensitiveTOTPValue},
		samlSensitiveRecoveryField: {samlSensitiveRecoveryValue},
	})
	sp := &config.SAML2ServiceProvider{}

	populateSAMLSessionAttributes(session, user, sp)

	attrs := samlAttributesByName(session.CustomAttributes)
	for _, name := range []string{samlSensitiveTOTPField, samlSensitiveRecoveryField} {
		if _, found := attrs[name]; found {
			t.Fatalf("SAML assertion attributes unexpectedly included sensitive key %q", name)
		}
	}

	assertSAMLAttributeValue(t, attrs, "email", "alice@example.com")
}

func TestSAMLUnrestrictedAttributesSuppressCamelCaseSecrets(t *testing.T) {
	session := &saml.Session{}
	sensitiveAttributes := map[string][]any{
		"userPassword": {"{SSHA}not-for-output"},
		"clientSecret": {"oidc-secret-not-for-output"},
	}

	userAttributes := map[string][]any{
		"displayName": {"Alice Example"},
	}

	for name, values := range sensitiveAttributes {
		userAttributes[name] = values
	}

	user := newSAMLAttributeUser(userAttributes)
	sp := &config.SAML2ServiceProvider{}

	populateSAMLSessionAttributes(session, user, sp)

	attrs := samlAttributesByName(session.CustomAttributes)
	for name := range sensitiveAttributes {
		if _, found := attrs[name]; found {
			t.Fatalf("SAML assertion attributes unexpectedly included sensitive key %q", name)
		}
	}

	assertSAMLAttributeValue(t, attrs, "displayName", "Alice Example")
}

func TestSAMLUnrestrictedAttributesPreservesAllowedAttribute(t *testing.T) {
	session := &saml.Session{}
	user := newSAMLAttributeUser(map[string][]any{
		"email":       {"alice@example.com"},
		"displayName": {"Alice Example"},
	})
	sp := &config.SAML2ServiceProvider{}

	populateSAMLSessionAttributes(session, user, sp)

	attrs := samlAttributesByName(session.CustomAttributes)
	assertSAMLAttributeValue(t, attrs, "email", "alice@example.com")
	assertSAMLAttributeValue(t, attrs, "displayName", "Alice Example")
}

func TestSAMLHandler_Metadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Generate a self-signed certificate for the test
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test IDP"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	entityID := "https://auth.example.com/saml"
	cfg := &mockSAMLCfg{
		entityID:    entityID,
		certificate: string(certPEM),
		key:         string(keyPEM),
	}

	d := &deps.Deps{
		Cfg:    cfg,
		Logger: slog.Default(),
	}
	h := NewSAMLHandler(d, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/saml/metadata", nil)

	h.Metadata(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), entityID)
}

func newSAMLAttributeUser(attributes bktype.AttributeMapping) *backend.User {
	return &backend.User{
		Name:              "alice",
		DisplayName:       "Alice Example",
		Attributes:        attributes,
		TOTPSecretField:   samlSensitiveTOTPField,
		TOTPRecoveryField: samlSensitiveRecoveryField,
	}
}

func samlAttributesByName(attributes []saml.Attribute) map[string]string {
	result := make(map[string]string, len(attributes))
	for _, attr := range attributes {
		if len(attr.Values) == 0 {
			continue
		}

		result[attr.Name] = attr.Values[0].Value
	}

	return result
}

func assertSAMLAttributeValue(t *testing.T, attrs map[string]string, name string, want string) {
	t.Helper()

	if got := attrs[name]; got != want {
		t.Fatalf("SAML attribute %q = %q, want %q", name, got, want)
	}
}

func TestBuildSPKeyDescriptors(t *testing.T) {
	// Generate a self-signed certificate for tests
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test SP"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	t.Run("NoCert", func(t *testing.T) {
		sp := &config.SAML2ServiceProvider{
			EntityID: "https://sp.example.com",
			ACSURL:   "https://sp.example.com/acs",
		}

		kds, err := buildSPKeyDescriptors(sp)

		assert.NoError(t, err)
		assert.Nil(t, kds)
	})

	t.Run("WithValidCert", func(t *testing.T) {
		sp := &config.SAML2ServiceProvider{
			EntityID: "https://sp.example.com",
			ACSURL:   "https://sp.example.com/acs",
			Cert:     string(certPEM),
		}

		kds, err := buildSPKeyDescriptors(sp)

		assert.NoError(t, err)
		assert.Len(t, kds, 1)
		assert.Empty(t, kds[0].Use, "Use should be empty for dual-use (signing + encryption)")
		assert.NotEmpty(t, kds[0].KeyInfo.X509Data.X509Certificates[0].Data)
	})

	t.Run("WithInvalidPEM", func(t *testing.T) {
		sp := &config.SAML2ServiceProvider{
			EntityID: "https://sp.example.com",
			ACSURL:   "https://sp.example.com/acs",
			Cert:     "not-a-valid-pem",
		}

		_, err := buildSPKeyDescriptors(sp)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse SP certificate PEM")
	})
}

func TestSAML_Routes_HaveLuaContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &mockSAMLCfg{entityID: "test", certificate: "test"}
	d := &deps.Deps{Cfg: cfg}
	h := NewSAMLHandler(d, nil)

	r := gin.New()
	runtime, _, _ := seedCanonicalIDPFlow(t, nil)
	h.Register(r, runtime)

	routes := []string{"/saml/metadata", "/saml/sso"}
	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			// Let's define r and the test to be more precise
			r := gin.New()

			var capturedCtx *gin.Context

			r.Use(func(c *gin.Context) {
				c.Next()
				capturedCtx = c
			})
			h.Register(r, runtime)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", path, nil)
			r.ServeHTTP(w, req)

			_, exists := capturedCtx.Get(definitions.CtxDataExchangeKey)
			assert.True(t, exists, "Lua context should be set for path: %s", path)

			svc, _ := capturedCtx.Get(definitions.CtxServiceKey)
			assert.Equal(t, definitions.ServIDP, svc)
		})
	}
}

func TestSAMLHandler_registerSLOParticipantSession(t *testing.T) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	cfg := &mockSAMLCfg{redisPrefix: "test:"}

	h := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	now := time.Now().UTC()
	samlSession := &saml.Session{
		NameID:     "alice@example.com",
		Index:      "_idx",
		CreateTime: now,
		ExpireTime: now.Add(-1 * time.Minute),
	}

	mock.Regexp().ExpectSet(`test:idp:saml:slo:participant:alice:[a-f0-9]{64}`, `.+`, time.Hour).SetVal("OK")
	mock.Regexp().ExpectSAdd(`test:idp:saml:slo:index:alice`, `test:idp:saml:slo:participant:alice:[a-f0-9]{64}`).SetVal(1)
	mock.ExpectExpireNX("test:idp:saml:slo:index:alice", time.Hour).SetVal(true)
	mock.ExpectExpireGT("test:idp:saml:slo:index:alice", time.Hour).SetVal(true)

	err := h.registerSLOParticipantSession(t.Context(), "alice", "https://sp.example.com", samlSession)
	if !assert.NoError(t, err) {
		return
	}

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_deleteSLOParticipantSessionsByAccount(t *testing.T) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	cfg := &mockSAMLCfg{redisPrefix: "test:"}

	h := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	indexKey := "test:idp:saml:slo:index:alice"
	key1 := "test:idp:saml:slo:participant:alice:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	key2 := "test:idp:saml:slo:participant:alice:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	mock.ExpectSMembers(indexKey).SetVal([]string{key1, key2})
	mock.ExpectDel(key1).SetVal(1)
	mock.ExpectDel(key2).SetVal(1)
	mock.ExpectDel(indexKey).SetVal(1)

	err := h.deleteSLOParticipantSessionsByAccount(t.Context(), "alice")
	if !assert.NoError(t, err) {
		return
	}

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRouteSLOInboundMessage(t *testing.T) {
	t.Parallel()

	for _, tc := range sloInboundMessageRouteCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertSLOInboundMessageRouteCase(t, tc)
		})
	}
}

type sloInboundMessageRouteCase struct {
	name        string
	method      string
	target      string
	contentType string
	body        string
	wantType    sloMessageType
	wantBinding string
	wantPayload string
	wantRelay   string
	wantErr     string
}

// sloInboundMessageRouteCases returns redirect and POST SLO routing fixtures.
func sloInboundMessageRouteCases() []sloInboundMessageRouteCase {
	testCases := sloInboundMessageSuccessRouteCases()

	return append(testCases, sloInboundMessageRejectRouteCases()...)
}

// sloInboundMessageSuccessRouteCases returns accepted SLO routing fixtures.
func sloInboundMessageSuccessRouteCases() []sloInboundMessageRouteCase {
	return []sloInboundMessageRouteCase{
		{
			name:        "GET redirect logout request",
			method:      http.MethodGet,
			target:      "/saml/slo?SAMLRequest=req-123",
			wantType:    sloMessageTypeRequest,
			wantBinding: "redirect",
			wantPayload: "req-123",
		},
		{
			name:        "GET redirect logout response",
			method:      http.MethodGet,
			target:      "/saml/slo?SAMLResponse=resp-123&RelayState=state-1",
			wantType:    sloMessageTypeResponse,
			wantBinding: "redirect",
			wantPayload: "resp-123",
			wantRelay:   "state-1",
		},
		{
			name:        "POST form logout request",
			method:      http.MethodPost,
			target:      "/saml/slo",
			contentType: "application/x-www-form-urlencoded",
			body:        "SAMLRequest=req-1&RelayState=state-2",
			wantType:    sloMessageTypeRequest,
			wantBinding: "post",
			wantPayload: "req-1",
			wantRelay:   "state-2",
		},
		{
			name:        "POST form logout response",
			method:      http.MethodPost,
			target:      "/saml/slo",
			contentType: "application/x-www-form-urlencoded",
			body:        "SAMLResponse=resp-1",
			wantType:    sloMessageTypeResponse,
			wantBinding: "post",
			wantPayload: "resp-1",
		},
	}
}

// sloInboundMessageRejectRouteCases returns rejected SLO routing fixtures.
func sloInboundMessageRejectRouteCases() []sloInboundMessageRouteCase {
	testCases := sloInboundMessageMissingRejectRouteCases()

	return append(testCases, sloInboundMessageInvalidRejectRouteCases()...)
}

// sloInboundMessageMissingRejectRouteCases returns missing/ambiguous payload cases.
func sloInboundMessageMissingRejectRouteCases() []sloInboundMessageRouteCase {
	return []sloInboundMessageRouteCase{
		{
			name:    "GET missing payload",
			method:  http.MethodGet,
			target:  "/saml/slo",
			wantErr: "missing SAMLRequest/SAMLResponse payload",
		},
		{
			name:        "POST missing payload",
			method:      http.MethodPost,
			target:      "/saml/slo",
			contentType: "application/x-www-form-urlencoded",
			body:        "",
			wantErr:     "missing SAMLRequest/SAMLResponse payload",
		},
		{
			name:    "GET ambiguous request and response",
			method:  http.MethodGet,
			target:  "/saml/slo?SAMLRequest=req&SAMLResponse=resp",
			wantErr: "must not be present together",
		},
		{
			name:        "POST ambiguous request and response",
			method:      http.MethodPost,
			target:      "/saml/slo",
			contentType: "application/x-www-form-urlencoded",
			body:        "SAMLRequest=req&SAMLResponse=resp",
			wantErr:     "must not be present together",
		},
	}
}

// sloInboundMessageInvalidRejectRouteCases returns malformed routing cases.
func sloInboundMessageInvalidRejectRouteCases() []sloInboundMessageRouteCase {
	return []sloInboundMessageRouteCase{
		{
			name:    "GET duplicated SAMLRequest",
			method:  http.MethodGet,
			target:  "/saml/slo?SAMLRequest=a&SAMLRequest=b",
			wantErr: "parameter SAMLRequest is duplicated",
		},
		{
			name:        "POST duplicated SAMLResponse",
			method:      http.MethodPost,
			target:      "/saml/slo",
			contentType: "application/x-www-form-urlencoded",
			body:        "SAMLResponse=a&SAMLResponse=b",
			wantErr:     "parameter SAMLResponse is duplicated",
		},
		{
			name:    "GET empty SAMLRequest",
			method:  http.MethodGet,
			target:  "/saml/slo?SAMLRequest=%20",
			wantErr: "parameter SAMLRequest is empty",
		},
		{
			name:        "POST invalid form encoding",
			method:      http.MethodPost,
			target:      "/saml/slo",
			contentType: "application/x-www-form-urlencoded",
			body:        "SAMLRequest=%zz",
			wantErr:     "parse form payload",
		},
		{
			name:    "unsupported method",
			method:  http.MethodPut,
			target:  "/saml/slo?SAMLRequest=req",
			wantErr: "unsupported slo method",
		},
	}
}

// assertSLOInboundMessageRouteCase checks one SLO inbound routing fixture.
func assertSLOInboundMessageRouteCase(t *testing.T, tc sloInboundMessageRouteCase) {
	t.Helper()

	req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
	if tc.contentType != "" {
		req.Header.Set("Content-Type", tc.contentType)
	}

	message, err := routeSLOInboundMessage(req)
	if tc.wantErr != "" {
		assert.Error(t, err)
		assert.ErrorContains(t, err, tc.wantErr)
		assert.Nil(t, message)

		return
	}

	if !assert.NoError(t, err) {
		return
	}

	assert.NotNil(t, message)
	assert.Equal(t, tc.wantType, message.MessageType)
	assert.Equal(t, tc.wantBinding, string(message.Binding))
	assert.Equal(t, tc.wantPayload, message.Payload)
	assert.Equal(t, tc.wantRelay, message.RelayState)
}

func mustGenerateRSACertificate(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
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

	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})

	return privateKey, certificate, certificatePEM
}

func mustEncodeRSAPrivateKeyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()

	if key == nil {
		t.Fatal("private key is nil")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func mustBuildSAMLAuthnRedirectTarget(t *testing.T, spEntityID, spACSURL, idpSSOURL string) string {
	t.Helper()

	return mustBuildSAMLAuthnRedirectTargetWithSigning(t, spEntityID, spACSURL, idpSSOURL, nil, nil, "")
}

func mustBuildSAMLAuthnRedirectTargetWithSigning(
	t *testing.T,
	spEntityID string,
	spACSURL string,
	idpSSOURL string,
	signingKey crypto.Signer,
	signingCertificate *x509.Certificate,
	signatureMethod string,
) string {
	t.Helper()

	metadataURL, err := url.Parse(spEntityID)
	if err != nil {
		t.Fatalf("failed to parse SP entity ID: %v", err)
	}

	acsURL, err := url.Parse(spACSURL)
	if err != nil {
		t.Fatalf("failed to parse SP ACS URL: %v", err)
	}

	serviceProvider := &saml.ServiceProvider{
		EntityID:        spEntityID,
		MetadataURL:     *metadataURL,
		AcsURL:          *acsURL,
		Key:             signingKey,
		Certificate:     signingCertificate,
		SignatureMethod: signatureMethod,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: "https://auth.example.com/saml/metadata",
			IDPSSODescriptors: []saml.IDPSSODescriptor{
				{
					SingleSignOnServices: []saml.Endpoint{
						{
							Binding:  saml.HTTPRedirectBinding,
							Location: idpSSOURL,
						},
					},
				},
			},
		},
	}

	redirectURL, err := serviceProvider.MakeRedirectAuthenticationRequest("relay-state")
	if err != nil {
		t.Fatalf("failed to create SAML AuthnRequest: %v", err)
	}

	return redirectURL.String()
}

type fakeSAMLIdentityProvider struct {
	sp          config.SAML2ServiceProvider
	user        *backend.User
	err         error
	userLookups int
}

func (f *fakeSAMLIdentityProvider) FindSAMLServiceProvider(entityID string) (*config.SAML2ServiceProvider, bool) {
	if configSp, ok := config.FindSAMLServiceProviderByEntityID([]config.SAML2ServiceProvider{f.sp}, entityID); ok {
		return configSp, true
	}

	return nil, false
}

func (f *fakeSAMLIdentityProvider) GetUserByUsernameForSAML(
	_ *gin.Context,
	username string,
	_ *config.SAML2ServiceProvider,
) (*backend.User, error) {
	f.userLookups++
	if f.err != nil {
		return nil, f.err
	}

	if f.user != nil {
		return f.user, nil
	}

	return &backend.User{
		Name:        username,
		DisplayName: "Alice Example",
		ID:          "alice-id",
		Attributes: bktype.AttributeMapping{
			"email": {"alice@example.com"},
		},
	}, nil
}

func newSAMLSSOTestFixture(
	t *testing.T,
	serviceProvider config.SAML2ServiceProvider,
	sessionData map[string]any,
) (*SAMLHandler, string, *mockCookieManager, *fakeSAMLIdentityProvider) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	if serviceProvider.EntityID == "" {
		serviceProvider.EntityID = "https://sp.example.com/saml/metadata"
	}

	if serviceProvider.ACSURL == "" {
		serviceProvider.ACSURL = "https://sp.example.com/saml/acs"
	}

	idpKey, _, idpCertPEM := mustGenerateRSACertificate(t, "saml-idp")
	cfg := &mockSAMLCfg{
		entityID:    "https://auth.example.com/saml/metadata",
		certificate: string(idpCertPEM),
		key:         string(mustEncodeRSAPrivateKeyPEM(t, idpKey)),
		sps:         []config.SAML2ServiceProvider{serviceProvider},
	}
	handlerDeps := &deps.Deps{
		Cfg:    cfg,
		Env:    config.NewEnvironmentConfig(),
		Logger: slog.Default(),
	}
	fakeIDP := &fakeSAMLIdentityProvider{sp: serviceProvider}
	handler := NewSAMLHandler(handlerDeps, fakeIDP)
	target := mustBuildSAMLAuthnRedirectTarget(t, serviceProvider.EntityID, serviceProvider.ACSURL, "https://auth.example.com/saml/sso")

	if sessionData == nil {
		sessionData = make(map[string]any)
	}

	return handler, target, &mockCookieManager{data: sessionData}, fakeIDP
}

// mustDecodeRedirectLogoutRequest inflates and decodes a redirect-binding LogoutRequest.
func mustDecodeRedirectLogoutRequest(t *testing.T, encodedRequest string) *saml.LogoutRequest {
	t.Helper()

	return mustDecodeRedirectSAMLMessage[saml.LogoutRequest](t, encodedRequest, "logout request")
}

// mustDecodeRedirectSAMLMessage decodes base64, inflates DEFLATE, and unmarshals a redirect SAML message.
func mustDecodeRedirectSAMLMessage[T any](t *testing.T, encodedMessage string, messageKind string) *T {
	t.Helper()

	rawMessage, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		t.Fatalf("failed to decode redirect %s base64: %v", messageKind, err)
	}

	reader := flate.NewReader(bytes.NewReader(rawMessage))
	defer func() { _ = reader.Close() }()

	xmlPayload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to inflate redirect %s: %v", messageKind, err)
	}

	var message T

	if err = xml.Unmarshal(xmlPayload, &message); err != nil {
		t.Fatalf("failed to unmarshal redirect %s XML: %v", messageKind, err)
	}

	return &message
}

type sloRedirectSignatureCase struct {
	name    string
	target  string
	wantErr string
}

type sloRedirectSignatureValidator func(*http.Request, *sloInboundMessage) error

// assertSLOInboundRedirectSignatureCases runs shared redirect-binding signature validation cases.
func assertSLOInboundRedirectSignatureCases(t *testing.T, testCases []sloRedirectSignatureCase, validator sloRedirectSignatureValidator) {
	t.Helper()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)

			message, err := routeSLOInboundMessage(req)
			if !assert.NoError(t, err) {
				return
			}

			err = validator(req, message)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

// assertSLODispatchBadRequest checks common SLO handler rejection responses.
func assertSLODispatchBadRequest(t *testing.T, target string, expectedBody string) {
	t.Helper()

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{},
	}, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, target, nil)

	handler.SLO(ctx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), expectedBody)
}

func mustExtractHiddenFormValue(t *testing.T, responseHTML string, fieldName string) string {
	t.Helper()

	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(fieldName) + `" value="([^"]*)"`)

	match := pattern.FindStringSubmatch(responseHTML)
	if len(match) != 2 {
		t.Fatalf("failed to extract hidden form field %q", fieldName)
	}

	return html.UnescapeString(match[1])
}

func mustBuildSignedRedirectLogoutTarget(t *testing.T, path string, logoutRequest *saml.LogoutRequest, relayState, sigAlg string, key *rsa.PrivateKey) string {
	t.Helper()

	deflated, err := logoutRequest.Deflate()
	if err != nil {
		t.Fatalf("failed to deflate logout request: %v", err)
	}

	rawSAMLRequest := url.QueryEscape(base64.StdEncoding.EncodeToString(deflated))
	rawSigAlg := url.QueryEscape(sigAlg)

	signedContent := "SAMLRequest=" + rawSAMLRequest

	if relayState != "" {
		signedContent += "&RelayState=" + url.QueryEscape(relayState)
	}

	signedContent += "&SigAlg=" + rawSigAlg

	signature := mustSignRedirectPayload(t, []byte(signedContent), sigAlg, key)
	query := signedContent + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))

	return path + "?" + query
}

func mustSignRedirectPayload(t *testing.T, payload []byte, sigAlg string, key *rsa.PrivateKey) []byte {
	t.Helper()

	var (
		hashType crypto.Hash
		digest   []byte
	)

	switch sigAlg {
	case dsig.RSASHA256SignatureMethod:
		sum := sha256.Sum256(payload)
		hashType = crypto.SHA256
		digest = sum[:]
	case dsig.RSASHA1SignatureMethod:
		sum := sha1.Sum(payload)
		hashType = crypto.SHA1
		digest = sum[:]
	default:
		t.Fatalf("unsupported test signature algorithm: %s", sigAlg)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hashType, digest)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	return signature
}

func mustBuildPostLogoutBody(t *testing.T, requestXML []byte) string {
	t.Helper()

	payload := base64.StdEncoding.EncodeToString(requestXML)

	return "SAMLRequest=" + url.QueryEscape(payload)
}

func mustBuildSignedLogoutRequestXML(t *testing.T, sp *saml.ServiceProvider, destination, nameID string) []byte {
	t.Helper()

	logoutRequest, err := sp.MakeLogoutRequest(destination, nameID)
	if err != nil {
		t.Fatalf("failed to create signed logout request: %v", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(logoutRequest.Element())

	requestXML, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("failed to serialize logout request: %v", err)
	}

	return requestXML
}

func sloTestParticipantIndexKey(redisPrefix, account string) string {
	return redisPrefix + "idp:saml:slo:index:" + url.QueryEscape(account)
}

func sloTestParticipantKey(redisPrefix, account, spEntityID string) string {
	sum := sha256.Sum256([]byte(spEntityID))

	return redisPrefix + "idp:saml:slo:participant:" + url.QueryEscape(account) + ":" + hex.EncodeToString(sum[:])
}

func sloTestReplayKey(redisPrefix, issuer, requestID string) string {
	replayScope := strings.TrimSpace(issuer) + "\x1f" + strings.TrimSpace(requestID)
	sum := sha256.Sum256([]byte(replayScope))

	return redisPrefix + "idp:saml:slo:replay:" + hex.EncodeToString(sum[:])
}

func TestSAMLHandler_validateInboundLogoutRequestProtocol_FieldValidation(t *testing.T) {
	spEntityID := "https://sp.example.com/saml/metadata"

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{},
	}, nil)

	baseRequest := func() *saml.LogoutRequest {
		return &saml.LogoutRequest{
			ID:           "id-protocol-field",
			Version:      "2.0",
			IssueInstant: saml.TimeNow().UTC(),
			Destination:  "https://auth.example.com/saml/slo",
			Issuer: &saml.Issuer{
				Value: spEntityID,
			},
			NameID: &saml.NameID{
				Value: "alice@example.com",
			},
		}
	}

	for _, tc := range logoutRequestProtocolFieldCases() {
		t.Run(tc.name, func(t *testing.T) {
			request := baseRequest()
			tc.mutate(request)

			err := handler.validateInboundLogoutRequestProtocol(t.Context(), request)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

type logoutRequestProtocolFieldCase struct {
	name    string
	mutate  func(request *saml.LogoutRequest)
	wantErr string
}

// logoutRequestProtocolFieldCases returns field-validation mutations for LogoutRequest.
func logoutRequestProtocolFieldCases() []logoutRequestProtocolFieldCase {
	return []logoutRequestProtocolFieldCase{
		{
			name: "missing request id",
			mutate: func(request *saml.LogoutRequest) {
				request.ID = ""
			},
			wantErr: "logout request id is missing",
		},
		{
			name: "missing issuer",
			mutate: func(request *saml.LogoutRequest) {
				request.Issuer = nil
			},
			wantErr: "logout request issuer is missing",
		},
		{
			name: "wrong destination",
			mutate: func(request *saml.LogoutRequest) {
				request.Destination = "https://evil.example.org/saml/slo"
			},
			wantErr: "does not match expected endpoint",
		},
		{
			name: "missing issue instant",
			mutate: func(request *saml.LogoutRequest) {
				request.IssueInstant = time.Time{}
			},
			wantErr: "IssueInstant is missing",
		},
		{
			name: "issue instant too old",
			mutate: func(request *saml.LogoutRequest) {
				request.IssueInstant = saml.TimeNow().UTC().Add(-(saml.MaxIssueDelay + time.Second))
			},
			wantErr: "IssueInstant is too old",
		},
		{
			name: "issue instant too far in the future",
			mutate: func(request *saml.LogoutRequest) {
				request.IssueInstant = saml.TimeNow().UTC().Add(saml.MaxClockSkew + time.Second)
			},
			wantErr: "IssueInstant is in the future",
		},
		{
			name: "not on or after expired",
			mutate: func(request *saml.LogoutRequest) {
				expired := saml.TimeNow().UTC().Add(-(saml.MaxClockSkew + time.Second))
				request.NotOnOrAfter = &expired
			},
			wantErr: "NotOnOrAfter is expired",
		},
		{
			name: "missing name id",
			mutate: func(request *saml.LogoutRequest) {
				request.NameID = nil
			},
			wantErr: "logout request NameID is missing",
		},
	}
}

func TestSAMLHandler_validateInboundLogoutRequestProtocol_RegistryAndReplay(t *testing.T) {
	const redisPrefix = "test:"

	account := "alice@example.com"
	spEntityID := "https://sp.example.com/saml/metadata"

	for _, tc := range logoutRequestRegistryReplayCases(account, spEntityID) {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			redisClient := rediscli.NewTestClient(db)

			handler := NewSAMLHandler(&deps.Deps{
				Cfg:   &mockSAMLCfg{redisPrefix: redisPrefix},
				Redis: redisClient,
			}, nil)

			expectLogoutRequestProtocolRedis(t, mock, redisPrefix, account, tc)

			err := handler.validateInboundLogoutRequestProtocol(t.Context(), tc.request)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

type logoutRequestRegistryReplayCase struct {
	name         string
	request      *saml.LogoutRequest
	participants []slodomain.ParticipantSession
	replayStored *bool
	wantErr      string
}

// logoutRequestRegistryReplayCases returns registry and replay validation cases.
func logoutRequestRegistryReplayCases(account, spEntityID string) []logoutRequestRegistryReplayCase {
	trueValue := true
	falseValue := false
	sessionIndex1 := "_idx-1"
	sessionIndex2 := "_idx-2"
	participant := logoutRequestProtocolParticipant(account, spEntityID, sessionIndex1)

	return []logoutRequestRegistryReplayCase{
		{
			name:         "success with matching session index",
			request:      newLogoutRequestProtocolTestRequest(account, "id-protocol-success", spEntityID, &sessionIndex1),
			participants: []slodomain.ParticipantSession{participant},
			replayStored: &trueValue,
		},
		{
			name:         "success without session index uses issuer mapping",
			request:      newLogoutRequestProtocolTestRequest(account, "id-protocol-success-no-session-index", spEntityID, nil),
			participants: []slodomain.ParticipantSession{participant},
			replayStored: &trueValue,
		},
		{
			name:    "missing participant sessions",
			request: newLogoutRequestProtocolTestRequest(account, "id-protocol-no-session", spEntityID, nil),
			wantErr: "no active SLO participant session for NameID",
		},
		{
			name:         "issuer does not match participant",
			request:      newLogoutRequestProtocolTestRequest(account, "id-protocol-issuer-mismatch", "https://other-sp.example.com/saml/metadata", nil),
			participants: []slodomain.ParticipantSession{participant},
			wantErr:      "no active SLO participant session for issuer",
		},
		{
			name:         "session index does not match participant",
			request:      newLogoutRequestProtocolTestRequest(account, "id-protocol-session-mismatch", spEntityID, &sessionIndex2),
			participants: []slodomain.ParticipantSession{participant},
			wantErr:      "session index",
		},
		{
			name:         "replay detected",
			request:      newLogoutRequestProtocolTestRequest(account, "id-protocol-replay", spEntityID, nil),
			participants: []slodomain.ParticipantSession{participant},
			replayStored: &falseValue,
			wantErr:      "replay detected",
		},
	}
}

// newLogoutRequestProtocolTestRequest builds the protocol validation baseline request.
func newLogoutRequestProtocolTestRequest(account, requestID, issuer string, sessionIndex *string) *saml.LogoutRequest {
	request := &saml.LogoutRequest{
		ID:           requestID,
		Version:      "2.0",
		IssueInstant: saml.TimeNow().UTC(),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Value: issuer,
		},
		NameID: &saml.NameID{
			Value: account,
		},
	}

	if sessionIndex != nil {
		request.SessionIndex = &saml.SessionIndex{Value: *sessionIndex}
	}

	return request
}

// logoutRequestProtocolParticipant builds one active participant fixture.
func logoutRequestProtocolParticipant(account, spEntityID, sessionIndex string) slodomain.ParticipantSession {
	return slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   spEntityID,
		NameID:       account,
		SessionIndex: sessionIndex,
		AuthnInstant: time.Now().UTC(),
	}
}

// expectLogoutRequestProtocolRedis registers Redis expectations for one protocol case.
func expectLogoutRequestProtocolRedis(
	t *testing.T,
	mock redismock.ClientMock,
	redisPrefix string,
	account string,
	tc logoutRequestRegistryReplayCase,
) {
	t.Helper()

	indexKey := sloTestParticipantIndexKey(redisPrefix, account)
	participantKeys := make([]string, 0, len(tc.participants))

	for _, participant := range tc.participants {
		participantKeys = append(participantKeys, sloTestParticipantKey(redisPrefix, participant.Account, participant.SPEntityID))
	}

	mock.ExpectSMembers(indexKey).SetVal(participantKeys)

	for idx, participant := range tc.participants {
		rawSession, err := json.Marshal(participant)
		if !assert.NoError(t, err) {
			return
		}

		mock.ExpectGet(participantKeys[idx]).SetVal(string(rawSession))
	}

	if tc.replayStored == nil {
		return
	}

	replayKey := sloTestReplayKey(redisPrefix, tc.request.Issuer.Value, tc.request.ID)
	mock.ExpectSetNX(replayKey, "1", time.Hour).SetVal(*tc.replayStored)
}

func TestSAMLHandler_validateInboundLogoutRequestSignature_Redirect(t *testing.T) {
	spEntityID := "https://sp.example.com/saml/metadata"
	spKey, _, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: spEntityID,
					ACSURL:   "https://sp.example.com/saml/acs",
					Cert:     string(spCertPEM),
				},
			},
		},
		Logger: slog.Default(),
	}, nil)

	testCases := logoutRequestRedirectSignatureCases(t, spEntityID, spKey)
	assertSLOInboundRedirectSignatureCases(t, testCases, func(req *http.Request, message *sloInboundMessage) error {
		_, err := handler.validateInboundLogoutRequestSignature(req, message)

		return err
	})
}

// logoutRequestRedirectSignatureCases builds redirect-binding signature cases.
func logoutRequestRedirectSignatureCases(t *testing.T, spEntityID string, spKey *rsa.PrivateKey) []sloRedirectSignatureCase {
	t.Helper()

	logoutRequest := &saml.LogoutRequest{
		ID:           "id-redirect-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  spEntityID,
		},
		NameID: &saml.NameID{
			Value: "alice@example.com",
		},
	}

	validTarget := mustBuildSignedRedirectLogoutTarget(
		t,
		"/saml/slo",
		logoutRequest,
		"relay-state",
		dsig.RSASHA256SignatureMethod,
		spKey,
	)

	sha1Target := mustBuildSignedRedirectLogoutTarget(
		t,
		"/saml/slo",
		logoutRequest,
		"relay-state",
		dsig.RSASHA1SignatureMethod,
		spKey,
	)

	return []sloRedirectSignatureCase{
		{
			name:   "valid signature",
			target: validTarget,
		},
		{
			name:    "tampered relay state",
			target:  strings.Replace(validTarget, "RelayState=relay-state", "RelayState=tampered", 1),
			wantErr: "invalid redirect logout request signature",
		},
		{
			name:    "unsupported SHA-1 signature algorithm",
			target:  sha1Target,
			wantErr: "unsupported redirect signature algorithm",
		},
		{
			name:    "duplicate signature parameter",
			target:  validTarget + "&Signature=AAAA",
			wantErr: "duplicate parameter \"Signature\"",
		},
	}
}

func TestSAMLHandler_validateInboundLogoutRequestSignature_Redirect_OptionalUnsigned(t *testing.T) {
	spEntityID := "https://sp.example.com/saml/metadata"
	unsigned := false

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID:             spEntityID,
					ACSURL:               "https://sp.example.com/saml/acs",
					LogoutRequestsSigned: &unsigned,
				},
			},
		},
		Logger: slog.Default(),
	}, nil)

	target := (&saml.LogoutRequest{
		ID:           "id-redirect-unsigned",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  spEntityID,
		},
		NameID: &saml.NameID{
			Value: "alice@example.com",
		},
	}).Redirect("relay-state").String()

	req := httptest.NewRequest(http.MethodGet, target, nil)

	message, err := routeSLOInboundMessage(req)
	if !assert.NoError(t, err) {
		return
	}

	_, err = handler.validateInboundLogoutRequestSignature(req, message)
	assert.NoError(t, err)
}

func TestSAMLHandler_validateInboundLogoutRequestSignature_Redirect_DefaultUnsigned(t *testing.T) {
	spEntityID := "https://sp.example.com/saml/metadata"

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: spEntityID,
					ACSURL:   "https://sp.example.com/saml/acs",
				},
			},
		},
		Logger: slog.Default(),
	}, nil)

	target := (&saml.LogoutRequest{
		ID:           "id-redirect-default-unsigned",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  spEntityID,
		},
		NameID: &saml.NameID{
			Value: "alice@example.com",
		},
	}).Redirect("relay-state").String()

	req := httptest.NewRequest(http.MethodGet, target, nil)

	message, err := routeSLOInboundMessage(req)
	if !assert.NoError(t, err) {
		return
	}

	_, err = handler.validateInboundLogoutRequestSignature(req, message)
	assert.NoError(t, err)
}

func TestSAMLHandler_validateInboundLogoutRequestSignature_POST(t *testing.T) {
	spEntityID := "https://sp.example.com/saml/metadata"
	destination := "https://auth.example.com/saml/slo"

	spKey, spCert, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: spEntityID,
					ACSURL:   "https://sp.example.com/saml/acs",
					Cert:     string(spCertPEM),
				},
			},
		},
		Logger: slog.Default(),
	}, nil)

	testCases := logoutRequestPostSignatureCases(t, spEntityID, destination, spKey, spCert)
	assertSLOInboundPostSignatureCases(t, handler, testCases)
}

type sloPostSignatureCase struct {
	name    string
	body    string
	wantErr string
}

// logoutRequestPostSignatureCases builds POST-binding XML signature cases.
func logoutRequestPostSignatureCases(
	t *testing.T,
	spEntityID string,
	destination string,
	spKey *rsa.PrivateKey,
	spCert *x509.Certificate,
) []sloPostSignatureCase {
	t.Helper()

	spURL, err := url.Parse(spEntityID)
	if !assert.NoError(t, err) {
		return nil
	}

	acsURL, err := url.Parse("https://sp.example.com/saml/acs")
	if !assert.NoError(t, err) {
		return nil
	}

	newSP := func(signatureMethod string) *saml.ServiceProvider {
		return &saml.ServiceProvider{
			Key:             spKey,
			Certificate:     spCert,
			MetadataURL:     *spURL,
			IDPMetadata:     &saml.EntityDescriptor{EntityID: "https://auth.example.com/saml/metadata"},
			EntityID:        spEntityID,
			AcsURL:          *acsURL,
			SignatureMethod: signatureMethod,
		}
	}

	validXML := mustBuildSignedLogoutRequestXML(t, newSP(dsig.RSASHA256SignatureMethod), destination, "alice@example.com")

	tamperedXML := bytes.Replace(validXML, []byte("alice@example.com"), []byte("mallory@example.com"), 1)
	if bytes.Equal(validXML, tamperedXML) {
		t.Fatal("expected tampered logout request payload to differ")
	}

	sha1XML := mustBuildSignedLogoutRequestXML(t, newSP(dsig.RSASHA1SignatureMethod), destination, "alice@example.com")

	return []sloPostSignatureCase{
		{
			name: "valid XML signature",
			body: mustBuildPostLogoutBody(t, validXML),
		},
		{
			name:    "tampered XML payload",
			body:    mustBuildPostLogoutBody(t, tamperedXML),
			wantErr: "cannot validate LogoutRequest XML signature",
		},
		{
			name:    "unsupported SHA-1 XML signature algorithm",
			body:    mustBuildPostLogoutBody(t, sha1XML),
			wantErr: "unsupported XML signature algorithm",
		},
	}
}

// assertSLOInboundPostSignatureCases runs shared POST-binding signature cases.
func assertSLOInboundPostSignatureCases(t *testing.T, handler *SAMLHandler, testCases []sloPostSignatureCase) {
	t.Helper()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			message, err := routeSLOInboundMessage(req)
			if !assert.NoError(t, err) {
				return
			}

			_, err = handler.validateInboundLogoutRequestSignature(req, message)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestSAMLHandler_SLOPayloadValidationAndDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	t.Run("returns 404 when slo is disabled", func(t *testing.T) {
		disabled := false
		handler := NewSAMLHandler(&deps.Deps{
			Cfg: &mockSAMLCfg{
				sloEnabled: &disabled,
			},
		}, nil)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/saml/slo?SAMLRequest=req-1", nil)

		handler.SLO(ctx)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "SAML SLO endpoint is disabled")
	})

	t.Run("rejects missing payload with 400", func(t *testing.T) {
		assertSLODispatchBadRequest(t, "/saml/slo", "Invalid SAML SLO payload")
	})

	t.Run("rejects unsigned logout request with 400", func(t *testing.T) {
		assertSLODispatchBadRequest(t, "/saml/slo?SAMLRequest=req-1", "Invalid SAML LogoutRequest signature")
	})

}

type signedRedirectSLOFixture struct {
	handler     *SAMLHandler
	mock        redismock.ClientMock
	idpCert     *x509.Certificate
	spEntityID  string
	spSLOURL    string
	idpEntityID string
	requestID   string
	relayState  string
	target      string
}

// newSignedRedirectSLOFixture builds a signed Redirect-binding handler fixture.
func newSignedRedirectSLOFixture(
	t *testing.T,
	requestID string,
	relayState string,
	sessionIndex string,
	cleanupErr error,
) signedRedirectSLOFixture {
	t.Helper()

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	spEntityID := "https://sp.example.com/saml/metadata"
	spSLOURL := "https://sp.example.com/saml/slo"
	nameID := "alice@example.com"

	spKey, _, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "auth.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	expectSLOParticipantLookupAndCleanup(t, mock, nameID, spEntityID, requestID, sessionIndex, cleanupErr)

	handler := newSignedSLOTestHandler(t, redisClient, spEntityID, spSLOURL, spCertPEM, idpCertPEM, idpKeyPEM)
	logoutRequest := newSignedRedirectSLOLogoutRequest(requestID, spEntityID, nameID)
	target := mustBuildSignedRedirectLogoutTarget(t, "/saml/slo", logoutRequest, relayState, dsig.RSASHA256SignatureMethod, spKey)

	return signedRedirectSLOFixture{
		handler:     handler,
		mock:        mock,
		idpCert:     idpCert,
		spEntityID:  spEntityID,
		spSLOURL:    spSLOURL,
		idpEntityID: "https://auth.example.com/saml/metadata",
		requestID:   requestID,
		relayState:  relayState,
		target:      target,
	}
}

// expectSLOParticipantLookupAndCleanup registers SLO registry and cleanup expectations.
func expectSLOParticipantLookupAndCleanup(
	t *testing.T,
	mock redismock.ClientMock,
	nameID string,
	spEntityID string,
	requestID string,
	sessionIndex string,
	cleanupErr error,
) {
	t.Helper()

	participantKey := sloTestParticipantKey("test:", nameID, spEntityID)
	indexKey := sloTestParticipantIndexKey("test:", nameID)
	replayKey := sloTestReplayKey("test:", spEntityID, requestID)
	participantSession := logoutRequestProtocolParticipant(nameID, spEntityID, sessionIndex)

	rawSession, err := json.Marshal(participantSession)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectGet(participantKey).SetVal(string(rawSession))
	mock.ExpectSetNX(replayKey, "1", time.Hour).SetVal(true)

	if cleanupErr != nil {
		mock.ExpectSMembers(indexKey).SetErr(cleanupErr)

		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectDel(participantKey).SetVal(1)
	mock.ExpectDel(indexKey).SetVal(1)
}

// newSignedSLOTestHandler creates a SAML handler with one signed SP fixture.
func newSignedSLOTestHandler(
	t *testing.T,
	redisClient rediscli.Client,
	spEntityID string,
	spSLOURL string,
	spCertPEM []byte,
	idpCertPEM []byte,
	idpKeyPEM []byte,
) *SAMLHandler {
	t.Helper()

	return NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			entityID:    "https://auth.example.com/saml/metadata",
			certificate: string(idpCertPEM),
			key:         string(idpKeyPEM),
			redisPrefix: "test:",
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: spEntityID,
					ACSURL:   "https://sp.example.com/saml/acs",
					SLOURL:   spSLOURL,
					Cert:     string(spCertPEM),
				},
			},
		},
		Logger: slog.Default(),
		Redis:  redisClient,
	}, nil)
}

// newSignedRedirectSLOLogoutRequest creates the signed redirect test request.
func newSignedRedirectSLOLogoutRequest(requestID, spEntityID, nameID string) *saml.LogoutRequest {
	return &saml.LogoutRequest{
		ID:           requestID,
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  spEntityID,
		},
		NameID: &saml.NameID{
			Value: nameID,
		},
	}
}

func TestSAMLHandler_newValidatedSLOTransaction(t *testing.T) {
	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{},
	}, nil)

	request := &saml.LogoutRequest{
		ID: "request-1",
		NameID: &saml.NameID{
			Value: "alice@example.com",
		},
	}

	transaction, err := handler.newValidatedSLOTransaction(request, slodomain.SLOBindingRedirect)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "request-1", transaction.RootRequestID)
	assert.Equal(t, "alice@example.com", transaction.Account)
	assert.Equal(t, slodomain.SLOStatusValidated, transaction.Status)
	assert.Equal(t, slodomain.SLODirectionSPInitiated, transaction.Direction)
	assert.Equal(t, slodomain.SLOBindingRedirect, transaction.Binding)

	_, err = handler.newValidatedSLOTransaction(&saml.LogoutRequest{}, slodomain.SLOBindingRedirect)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "logout request id is missing")
}
