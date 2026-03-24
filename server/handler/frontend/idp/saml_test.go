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
	"fmt"
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
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
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

func (m *mockSAMLCfg) GetIdP() *config.IdPSection {
	return &config.IdPSection{
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
			SLOBackChannelEnabled:    m.sloBackChannelEnabled,
			SLOBackChannelTimeout:    m.sloRequestTimeout,
			SLOBackChannelMaxRetries: m.sloBackChannelRetries,
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
			Organization: []string{"Test IdP"},
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
	h.Register(r)

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
			h.Register(r)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", path, nil)
			r.ServeHTTP(w, req)

			_, exists := capturedCtx.Get(definitions.CtxDataExchangeKey)
			assert.True(t, exists, "Lua context should be set for path: %s", path)

			svc, _ := capturedCtx.Get(definitions.CtxServiceKey)
			assert.Equal(t, definitions.ServIdP, svc)
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

	testCases := []struct {
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
	}{
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

	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
		})
	}
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

func mustBuildSPLogoutResponseValidator(
	t *testing.T,
	spEntityID string,
	sloURL string,
	idpEntityID string,
	idpCert *x509.Certificate,
) *saml.ServiceProvider {
	t.Helper()

	metadataURL, err := url.Parse(spEntityID)
	if err != nil {
		t.Fatalf("failed to parse SP metadata URL: %v", err)
	}

	logoutURL, err := url.Parse(sloURL)
	if err != nil {
		t.Fatalf("failed to parse SP SLO URL: %v", err)
	}

	if idpCert == nil {
		t.Fatal("idp certificate is nil")
	}

	idpCertB64 := base64.StdEncoding.EncodeToString(idpCert.Raw)

	return &saml.ServiceProvider{
		MetadataURL: *metadataURL,
		SloURL:      *logoutURL,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: idpEntityID,
			IDPSSODescriptors: []saml.IDPSSODescriptor{
				{
					SSODescriptor: saml.SSODescriptor{
						RoleDescriptor: saml.RoleDescriptor{
							KeyDescriptors: []saml.KeyDescriptor{
								{
									Use: "signing",
									KeyInfo: saml.KeyInfo{
										X509Data: saml.X509Data{
											X509Certificates: []saml.X509Certificate{
												{Data: idpCertB64},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func mustDecodeRedirectLogoutResponse(t *testing.T, encodedResponse string) *saml.LogoutResponse {
	t.Helper()

	rawResponse, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		t.Fatalf("failed to decode redirect logout response base64: %v", err)
	}

	reader := flate.NewReader(bytes.NewReader(rawResponse))
	defer reader.Close()

	xmlPayload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to inflate redirect logout response: %v", err)
	}

	var response saml.LogoutResponse

	if err = xml.Unmarshal(xmlPayload, &response); err != nil {
		t.Fatalf("failed to unmarshal redirect logout response XML: %v", err)
	}

	return &response
}

func mustDecodePostLogoutResponse(t *testing.T, encodedResponse string) *saml.LogoutResponse {
	t.Helper()

	rawResponse, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		t.Fatalf("failed to decode post logout response base64: %v", err)
	}

	var response saml.LogoutResponse

	if err = xml.Unmarshal(rawResponse, &response); err != nil {
		t.Fatalf("failed to unmarshal post logout response XML: %v", err)
	}

	return &response
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

	testCases := []struct {
		name    string
		mutate  func(request *saml.LogoutRequest)
		wantErr string
	}{
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

	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			request := baseRequest()
			tc.mutate(request)

			err := handler.validateInboundLogoutRequestProtocol(t.Context(), request)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestSAMLHandler_validateInboundLogoutRequestProtocol_RegistryAndReplay(t *testing.T) {
	const redisPrefix = "test:"

	account := "alice@example.com"
	spEntityID := "https://sp.example.com/saml/metadata"

	baseRequest := func(requestID, issuer string, sessionIndex *string) *saml.LogoutRequest {
		req := &saml.LogoutRequest{
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
			req.SessionIndex = &saml.SessionIndex{Value: *sessionIndex}
		}

		return req
	}

	trueVal := true
	falseVal := false
	sessionIdx1 := "_idx-1"
	sessionIdx2 := "_idx-2"

	testCases := []struct {
		name         string
		request      *saml.LogoutRequest
		participants []slodomain.ParticipantSession
		replayStored *bool
		wantErr      string
	}{
		{
			name:    "success with matching session index",
			request: baseRequest("id-protocol-success", spEntityID, &sessionIdx1),
			participants: []slodomain.ParticipantSession{
				{
					Account:      account,
					SPEntityID:   spEntityID,
					NameID:       account,
					SessionIndex: sessionIdx1,
					AuthnInstant: saml.TimeNow().UTC(),
				},
			},
			replayStored: &trueVal,
		},
		{
			name:    "success without session index uses issuer mapping",
			request: baseRequest("id-protocol-success-no-session-index", spEntityID, nil),
			participants: []slodomain.ParticipantSession{
				{
					Account:      account,
					SPEntityID:   spEntityID,
					NameID:       account,
					SessionIndex: sessionIdx1,
					AuthnInstant: saml.TimeNow().UTC(),
				},
			},
			replayStored: &trueVal,
		},
		{
			name:         "missing participant sessions",
			request:      baseRequest("id-protocol-no-session", spEntityID, nil),
			participants: nil,
			wantErr:      "no active SLO participant session for NameID",
		},
		{
			name:    "issuer does not match participant",
			request: baseRequest("id-protocol-issuer-mismatch", "https://other-sp.example.com/saml/metadata", nil),
			participants: []slodomain.ParticipantSession{
				{
					Account:      account,
					SPEntityID:   spEntityID,
					NameID:       account,
					SessionIndex: sessionIdx1,
					AuthnInstant: saml.TimeNow().UTC(),
				},
			},
			wantErr: "no active SLO participant session for issuer",
		},
		{
			name:    "session index does not match participant",
			request: baseRequest("id-protocol-session-mismatch", spEntityID, &sessionIdx2),
			participants: []slodomain.ParticipantSession{
				{
					Account:      account,
					SPEntityID:   spEntityID,
					NameID:       account,
					SessionIndex: sessionIdx1,
					AuthnInstant: saml.TimeNow().UTC(),
				},
			},
			wantErr: "session index",
		},
		{
			name:    "replay detected",
			request: baseRequest("id-protocol-replay", spEntityID, nil),
			participants: []slodomain.ParticipantSession{
				{
					Account:      account,
					SPEntityID:   spEntityID,
					NameID:       account,
					SessionIndex: sessionIdx1,
					AuthnInstant: saml.TimeNow().UTC(),
				},
			},
			replayStored: &falseVal,
			wantErr:      "replay detected",
		},
	}

	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			redisClient := rediscli.NewTestClient(db)

			handler := NewSAMLHandler(&deps.Deps{
				Cfg:   &mockSAMLCfg{redisPrefix: redisPrefix},
				Redis: redisClient,
			}, nil)

			indexKey := sloTestParticipantIndexKey(redisPrefix, account)
			participantKeys := make([]string, 0, len(tc.participants))

			for _, participant := range tc.participants {
				participantKey := sloTestParticipantKey(redisPrefix, participant.Account, participant.SPEntityID)
				participantKeys = append(participantKeys, participantKey)
			}

			mock.ExpectSMembers(indexKey).SetVal(participantKeys)

			for idx, participant := range tc.participants {
				rawSession, err := json.Marshal(participant)
				if !assert.NoError(t, err) {
					return
				}

				mock.ExpectGet(participantKeys[idx]).SetVal(string(rawSession))
			}

			if tc.replayStored != nil {
				replayKey := sloTestReplayKey(redisPrefix, tc.request.Issuer.Value, tc.request.ID)
				mock.ExpectSetNX(replayKey, "1", time.Hour).SetVal(*tc.replayStored)
			}

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

	testCases := []struct {
		name    string
		target  string
		wantErr string
	}{
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

	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)

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

	spURL, err := url.Parse(spEntityID)
	if !assert.NoError(t, err) {
		return
	}

	acsURL, err := url.Parse("https://sp.example.com/saml/acs")
	if !assert.NoError(t, err) {
		return
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

	testCases := []struct {
		name    string
		body    string
		wantErr string
	}{
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
		handler := NewSAMLHandler(&deps.Deps{
			Cfg: &mockSAMLCfg{},
		}, nil)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/saml/slo", nil)

		handler.SLO(ctx)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid SAML SLO payload")
	})

	t.Run("rejects unsigned logout request with 400", func(t *testing.T) {
		handler := NewSAMLHandler(&deps.Deps{
			Cfg: &mockSAMLCfg{},
		}, nil)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/saml/slo?SAMLRequest=req-1", nil)

		handler.SLO(ctx)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid SAML LogoutRequest signature")
	})

	t.Run("dispatches signed logout request and returns signed redirect logout response", func(t *testing.T) {
		db, mock := redismock.NewClientMock()
		redisClient := rediscli.NewTestClient(db)

		spEntityID := "https://sp.example.com/saml/metadata"
		spSLOURL := "https://sp.example.com/saml/slo"
		spKey, _, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
		idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "auth.example.com")
		idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)
		nameID := "alice@example.com"
		requestID := "id-handler-1"
		relayState := "relay-state"

		participantKey := sloTestParticipantKey("test:", nameID, spEntityID)
		indexKey := sloTestParticipantIndexKey("test:", nameID)
		replayKey := sloTestReplayKey("test:", spEntityID, requestID)

		participantSession := slodomain.ParticipantSession{
			Account:      nameID,
			SPEntityID:   spEntityID,
			NameID:       nameID,
			SessionIndex: "_idx-handler",
			AuthnInstant: time.Now().UTC(),
		}

		rawSession, err := json.Marshal(participantSession)
		if !assert.NoError(t, err) {
			return
		}

		mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
		mock.ExpectGet(participantKey).SetVal(string(rawSession))
		mock.ExpectSetNX(replayKey, "1", time.Hour).SetVal(true)
		mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
		mock.ExpectDel(participantKey).SetVal(1)
		mock.ExpectDel(indexKey).SetVal(1)

		handler := NewSAMLHandler(&deps.Deps{
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

		logoutRequest := &saml.LogoutRequest{
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

		target := mustBuildSignedRedirectLogoutTarget(
			t,
			"/saml/slo",
			logoutRequest,
			relayState,
			dsig.RSASHA256SignatureMethod,
			spKey,
		)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, target, nil)

		handler.SLO(ctx)

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		locationURL, err := url.Parse(location)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, spSLOURL, locationURL.Scheme+"://"+locationURL.Host+locationURL.Path)
		assert.Equal(t, relayState, locationURL.Query().Get("RelayState"))

		rawSAMLResponse := locationURL.Query().Get("SAMLResponse")
		if !assert.NotEmpty(t, rawSAMLResponse) {
			return
		}

		response := mustDecodeRedirectLogoutResponse(t, rawSAMLResponse)
		assert.Equal(t, requestID, response.InResponseTo)
		assert.Equal(t, spSLOURL, response.Destination)
		if assert.NotNil(t, response.Issuer) {
			assert.Equal(t, "https://auth.example.com/saml/metadata", response.Issuer.Value)
		}
		assert.Equal(t, saml.StatusSuccess, response.Status.StatusCode.Value)
		assert.NotNil(t, response.Signature)

		validatorSP := mustBuildSPLogoutResponseValidator(
			t,
			spEntityID,
			spSLOURL,
			"https://auth.example.com/saml/metadata",
			idpCert,
		)

		assert.NoError(t, validatorSP.ValidateLogoutResponseRedirect(rawSAMLResponse))
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSAMLHandler_SLOSignedLogoutResponse_POST(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	spEntityID := "https://sp.example.com/saml/metadata"
	spACSURL := "https://sp.example.com/saml/acs"
	spSLOURL := "https://sp.example.com/saml/slo"
	nameID := "alice@example.com"
	relayState := "relay-post-state"

	spKey, spCert, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "auth.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	spMetadataURL, err := url.Parse(spEntityID)
	if !assert.NoError(t, err) {
		return
	}

	spACSParsedURL, err := url.Parse(spACSURL)
	if !assert.NoError(t, err) {
		return
	}

	requestSigningSP := &saml.ServiceProvider{
		Key:             spKey,
		Certificate:     spCert,
		MetadataURL:     *spMetadataURL,
		IDPMetadata:     &saml.EntityDescriptor{EntityID: "https://auth.example.com/saml/metadata"},
		EntityID:        spEntityID,
		AcsURL:          *spACSParsedURL,
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}

	requestXML := mustBuildSignedLogoutRequestXML(
		t,
		requestSigningSP,
		"https://auth.example.com/saml/slo",
		nameID,
	)

	var logoutRequest saml.LogoutRequest
	if err = xml.Unmarshal(requestXML, &logoutRequest); !assert.NoError(t, err) {
		return
	}

	participantKey := sloTestParticipantKey("test:", nameID, spEntityID)
	indexKey := sloTestParticipantIndexKey("test:", nameID)
	replayKey := sloTestReplayKey("test:", spEntityID, logoutRequest.ID)

	participantSession := slodomain.ParticipantSession{
		Account:      nameID,
		SPEntityID:   spEntityID,
		NameID:       nameID,
		SessionIndex: "_idx-handler-post",
		AuthnInstant: time.Now().UTC(),
	}

	rawSession, err := json.Marshal(participantSession)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectGet(participantKey).SetVal(string(rawSession))
	mock.ExpectSetNX(replayKey, "1", time.Hour).SetVal(true)
	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectDel(participantKey).SetVal(1)
	mock.ExpectDel(indexKey).SetVal(1)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			entityID:    "https://auth.example.com/saml/metadata",
			certificate: string(idpCertPEM),
			key:         string(idpKeyPEM),
			redisPrefix: "test:",
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: spEntityID,
					ACSURL:   spACSURL,
					SLOURL:   spSLOURL,
					Cert:     string(spCertPEM),
				},
			},
		},
		Logger: slog.Default(),
		Redis:  redisClient,
	}, nil)

	formBody := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(requestXML)) +
		"&RelayState=" + url.QueryEscape(relayState)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(formBody))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler.SLO(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "id=\"SAMLResponseForm\"")

	rawSAMLResponse := mustExtractHiddenFormValue(t, w.Body.String(), "SAMLResponse")
	assert.Equal(t, relayState, mustExtractHiddenFormValue(t, w.Body.String(), "RelayState"))

	response := mustDecodePostLogoutResponse(t, rawSAMLResponse)
	assert.Equal(t, logoutRequest.ID, response.InResponseTo)
	assert.Equal(t, spSLOURL, response.Destination)
	if assert.NotNil(t, response.Issuer) {
		assert.Equal(t, "https://auth.example.com/saml/metadata", response.Issuer.Value)
	}
	assert.Equal(t, saml.StatusSuccess, response.Status.StatusCode.Value)
	assert.NotNil(t, response.Signature)

	validatorSP := mustBuildSPLogoutResponseValidator(
		t,
		spEntityID,
		spSLOURL,
		"https://auth.example.com/saml/metadata",
		idpCert,
	)

	assert.NoError(t, validatorSP.ValidateLogoutResponseForm(rawSAMLResponse))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_SLOSignedLogoutResponse_PartialLogoutStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	spEntityID := "https://sp.example.com/saml/metadata"
	spSLOURL := "https://sp.example.com/saml/slo"
	nameID := "alice@example.com"
	requestID := "id-handler-partial"
	relayState := "relay-partial-state"

	spKey, _, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "auth.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	participantKey := sloTestParticipantKey("test:", nameID, spEntityID)
	indexKey := sloTestParticipantIndexKey("test:", nameID)
	replayKey := sloTestReplayKey("test:", spEntityID, requestID)

	participantSession := slodomain.ParticipantSession{
		Account:      nameID,
		SPEntityID:   spEntityID,
		NameID:       nameID,
		SessionIndex: "_idx-handler-partial",
		AuthnInstant: time.Now().UTC(),
	}

	rawSession, err := json.Marshal(participantSession)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectGet(participantKey).SetVal(string(rawSession))
	mock.ExpectSetNX(replayKey, "1", time.Hour).SetVal(true)
	mock.ExpectSMembers(indexKey).SetErr(fmt.Errorf("redis cleanup failure"))

	handler := NewSAMLHandler(&deps.Deps{
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

	logoutRequest := &saml.LogoutRequest{
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

	target := mustBuildSignedRedirectLogoutTarget(
		t,
		"/saml/slo",
		logoutRequest,
		relayState,
		dsig.RSASHA256SignatureMethod,
		spKey,
	)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, target, nil)

	handler.SLO(ctx)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	locationURL, err := url.Parse(location)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, spSLOURL, locationURL.Scheme+"://"+locationURL.Host+locationURL.Path)
	assert.Equal(t, relayState, locationURL.Query().Get("RelayState"))

	rawSAMLResponse := locationURL.Query().Get("SAMLResponse")
	if !assert.NotEmpty(t, rawSAMLResponse) {
		return
	}

	response := mustDecodeRedirectLogoutResponse(t, rawSAMLResponse)
	assert.Equal(t, requestID, response.InResponseTo)
	assert.Equal(t, saml.StatusResponder, response.Status.StatusCode.Value)
	if assert.NotNil(t, response.Status.StatusCode.StatusCode) {
		assert.Equal(t, saml.StatusPartialLogout, response.Status.StatusCode.StatusCode.Value)
	}
	assert.NotNil(t, response.Signature)

	validatorSP := mustBuildSPLogoutResponseValidator(
		t,
		spEntityID,
		spSLOURL,
		"https://auth.example.com/saml/metadata",
		idpCert,
	)

	err = validatorSP.ValidateLogoutResponseRedirect(rawSAMLResponse)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "status code was not")
	assert.NoError(t, mock.ExpectationsWereMet())
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

func TestSAMLHandler_performLocalSLOCleanup_Idempotent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			redisPrefix: "test:",
		},
		Logger: slog.Default(),
		Redis:  redisClient,
	}, nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:                "alice@example.com",
		definitions.SessionKeyIdPFlowID:              "flow-local-cleanup",
		definitions.SessionKeyIdPFlowType:            definitions.ProtoSAML,
		definitions.SessionKeyIdPSAMLEntityID:        "https://sp.example.com/saml/metadata",
		definitions.SessionKeyUsername:               "alice",
		definitions.SessionKeyMFAMethod:              "totp",
		definitions.SessionKeyRequireMFAFlow:         true,
		definitions.SessionKeyRequireMFAPending:      "webauthn",
		definitions.SessionKeyRequireMFAParentFlowID: "flow-parent",
	}}

	flowStateKey := "test:idp:flow:flow-local-cleanup"
	participantIndexKey := sloTestParticipantIndexKey("test:", "alice@example.com")

	mock.ExpectDel(flowStateKey).SetVal(1)
	mock.ExpectSMembers(participantIndexKey).SetVal(nil)
	mock.ExpectDel(participantIndexKey).SetVal(1)
	mock.ExpectSMembers(participantIndexKey).SetVal(nil)
	mock.ExpectDel(participantIndexKey).SetVal(1)

	transaction, err := slodomain.NewTransaction(
		"tx-local-cleanup",
		"request-local-cleanup",
		slodomain.SLODirectionSPInitiated,
		slodomain.SLOBindingRedirect,
		time.Now().UTC(),
	)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusValidated, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/saml/slo", nil)
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	handler.performLocalSLOCleanup(ctx, "alice@example.com", transaction)
	handler.performLocalSLOCleanup(ctx, "alice@example.com", transaction)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/logged_out", w.Header().Get("Location"))
	assert.Equal(t, slodomain.SLOStatusLocalDone, transaction.Status)
	assert.Empty(t, mgr.GetString(definitions.SessionKeyAccount, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyIdPFlowID, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""))
	assert.NoError(t, mock.ExpectationsWereMet())
}
