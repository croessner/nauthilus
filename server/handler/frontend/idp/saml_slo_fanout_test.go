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
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_Redirect(t *testing.T) {
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	cfg := newRedirectSLOFanoutConfig(idpCertPEM, idpKeyPEM)
	handler, mock := newSLOFanoutTestHandler(cfg)
	account := "alice@example.com"
	participantB, participantInvalid, participantA := redirectSLOFanoutParticipants(account)

	mustExpectSLOParticipantSessions(t, mock, "test:", account, participantB, participantInvalid, participantA)

	transaction := mustLocalDoneIDPFanoutTransaction(t, handler, account, slodomain.SLOBindingRedirect)
	result := mustOrchestrateIDPFanout(t, handler, transaction, account)

	assert.Equal(t, slodomain.SLOStatusFanoutRunning, transaction.Status)

	if assert.NotNil(t, result) {
		assert.Len(t, result.Dispatches, 2)
		assert.Len(t, result.Failures, 1)
		assert.Equal(t, "not-an-absolute-url", result.Failures[0].EntityID)
	}

	if !assert.Len(t, transaction.Participants, 2) {
		return
	}

	assert.Equal(t, "https://sp-a.example.com/metadata", result.Dispatches[0].Participant.EntityID)
	assert.Equal(t, "https://sp-b.example.com/metadata", result.Dispatches[1].Participant.EntityID)
	assertRedirectFanoutDispatches(t, result.Dispatches, transaction, idpCert, account)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_POST(t *testing.T) {
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	cfg := &mockSAMLCfg{
		entityID:    "https://auth.example.com/saml/metadata",
		certificate: string(idpCertPEM),
		key:         string(idpKeyPEM),
		redisPrefix: "test:",
		sps: []config.SAML2ServiceProvider{
			{
				EntityID: "https://sp-post.example.com/metadata",
				SLOURL:   "https://sp-post.example.com/saml/slo",
			},
		},
	}

	handler, mock := newSLOFanoutTestHandler(cfg)
	account := "bob@example.com"
	participant := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-post.example.com/metadata",
		NameID:       "bob-name-id",
		SessionIndex: "session-post",
		AuthnInstant: time.Date(2026, time.March, 18, 9, 0, 0, 0, time.UTC),
	}
	mustExpectSLOParticipantSessions(t, mock, "test:", account, participant)

	transaction := mustLocalDoneIDPFanoutTransaction(t, handler, account, slodomain.SLOBindingPost)
	result := mustOrchestrateIDPFanout(t, handler, transaction, account)

	if !assert.NotNil(t, result) {
		return
	}

	if !assert.Len(t, result.Dispatches, 1) {
		return
	}

	assert.Equal(t, slodomain.SLOStatusFanoutRunning, transaction.Status)
	assertPostFanoutDispatch(t, result.Dispatches[0], transaction, idpCert, "bob-name-id", "session-post")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_NoParticipants(t *testing.T) {
	idpKey, _, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	cfg := &mockSAMLCfg{
		entityID:    "https://auth.example.com/saml/metadata",
		certificate: string(idpCertPEM),
		key:         string(idpKeyPEM),
		redisPrefix: "test:",
	}

	handler, mock := newSLOFanoutTestHandler(cfg)
	account := "nobody@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)
	mock.ExpectSMembers(indexKey).SetVal(nil)

	transaction := mustLocalDoneIDPFanoutTransaction(t, handler, account, slodomain.SLOBindingRedirect)
	result := mustOrchestrateIDPFanout(t, handler, transaction, account)

	assert.NotNil(t, result)
	assert.Empty(t, result.Dispatches)
	assert.Empty(t, result.Failures)
	assert.Equal(t, slodomain.SLOStatusDone, transaction.Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_BackChannelSuccess(t *testing.T) {
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	receivedForm, backChannelServer := newBackChannelCaptureServer(t)
	defer backChannelServer.Close()

	cfg := newBackChannelSuccessSLOFanoutConfig(idpCertPEM, idpKeyPEM, backChannelServer.URL)
	handler, mock := newSLOFanoutTestHandler(cfg)
	account := "carol@example.com"
	participant := backChannelSuccessSLOParticipant(account)
	mustExpectSLOParticipantSessions(t, mock, "test:", account, participant)

	transaction := mustLocalDoneIDPFanoutTransaction(t, handler, account, slodomain.SLOBindingRedirect)
	result := mustOrchestrateIDPFanout(t, handler, transaction, account)

	assert.NotNil(t, result)
	assert.Empty(t, result.Dispatches)
	assert.Empty(t, result.Failures)
	assert.Equal(t, slodomain.SLOStatusDone, transaction.Status)

	if !assert.Len(t, transaction.Participants, 1) {
		return
	}

	assertBackChannelFanoutRequest(t, receivedForm, transaction, idpCert, "carol-name-id", "session-back")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_BackChannelFallbackToFrontChannel(t *testing.T) {
	idpKey, _, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	var attempts atomic.Int32

	backChannelServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		resp.WriteHeader(http.StatusBadGateway)
	}))
	defer backChannelServer.Close()

	enabled := true
	cfg := &mockSAMLCfg{
		entityID:              "https://auth.example.com/saml/metadata",
		certificate:           string(idpCertPEM),
		key:                   string(idpKeyPEM),
		redisPrefix:           "test:",
		sloBackChannelEnabled: &enabled,
		sloRequestTimeout:     time.Second,
		sloBackChannelRetries: 1,
		sps: []config.SAML2ServiceProvider{
			{
				EntityID:          "https://sp-fallback.example.com/metadata",
				SLOURL:            "https://sp-fallback.example.com/saml/slo",
				SLOBackChannelURL: backChannelServer.URL + "/saml/slo-back",
			},
		},
	}

	handler, mock := newSLOFanoutTestHandler(cfg)
	account := "dave@example.com"
	participant := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-fallback.example.com/metadata",
		NameID:       "dave-name-id",
		SessionIndex: "session-fallback",
		AuthnInstant: time.Date(2026, time.March, 18, 11, 0, 0, 0, time.UTC),
	}
	mustExpectSLOParticipantSessions(t, mock, "test:", account, participant)

	transaction := mustLocalDoneIDPFanoutTransaction(t, handler, account, slodomain.SLOBindingRedirect)
	result := mustOrchestrateIDPFanout(t, handler, transaction, account)

	if !assert.NotNil(t, result) {
		return
	}

	if !assert.Len(t, result.Dispatches, 1) {
		return
	}

	assert.Empty(t, result.Failures)
	assert.NotEmpty(t, result.Dispatches[0].RedirectURL)
	assert.Equal(t, slodomain.SLOStatusFanoutRunning, transaction.Status)
	assert.Equal(t, int32(2), attempts.Load())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLBackChannelDeliveryRedirectToLoopbackIsBlocked(t *testing.T) {
	var redirected atomic.Int32

	redirectTarget := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		resp.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	redirectingSP := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		resp.Header().Set("Location", redirectTarget.URL+"/metadata")
		resp.WriteHeader(http.StatusFound)
	}))
	defer redirectingSP.Close()

	delivery := newSLOBackChannelRedirectTestDelivery(redirectingSP.URL)
	err := delivery.run(t.Context())

	assert.Error(t, err)
	assert.Equal(t, int32(0), redirected.Load(), "back-channel delivery followed a redirect to loopback")
}

func TestSAMLBackChannelDeliveryRedirectChainIsNotFollowed(t *testing.T) {
	var (
		middleHits atomic.Int32
		finalHits  atomic.Int32
	)

	finalTarget := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		finalHits.Add(1)
		resp.WriteHeader(http.StatusOK)
	}))
	defer finalTarget.Close()

	middleTarget := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		middleHits.Add(1)
		resp.Header().Set("Location", finalTarget.URL+"/metadata")
		resp.WriteHeader(http.StatusFound)
	}))
	defer middleTarget.Close()

	redirectingSP := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		resp.Header().Set("Location", middleTarget.URL+"/saml/slo-back")
		resp.WriteHeader(http.StatusFound)
	}))
	defer redirectingSP.Close()

	delivery := newSLOBackChannelRedirectTestDelivery(redirectingSP.URL)
	err := delivery.run(t.Context())

	assert.Error(t, err)
	assert.Equal(t, int32(0), middleHits.Load(), "back-channel delivery followed the first redirect")
	assert.Equal(t, int32(0), finalHits.Load(), "back-channel delivery followed the redirect chain")
}

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_DisabledChannels(t *testing.T) {
	idpKey, _, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)
	frontChannelEnabled := false
	backChannelEnabled := false

	cfg := &mockSAMLCfg{
		entityID:              "https://auth.example.com/saml/metadata",
		certificate:           string(idpCertPEM),
		key:                   string(idpKeyPEM),
		redisPrefix:           "test:",
		sloFrontChannel:       &frontChannelEnabled,
		sloBackChannelEnabled: &backChannelEnabled,
	}

	handler, mock := newSLOFanoutTestHandler(cfg)
	account := "erin@example.com"
	participant := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-erin.example.com/metadata",
		NameID:       "erin-name-id",
		SessionIndex: "session-erin",
		AuthnInstant: time.Date(2026, time.March, 18, 11, 10, 0, 0, time.UTC),
	}
	mustExpectSLOParticipantSessions(t, mock, "test:", account, participant)

	transaction := mustLocalDoneIDPFanoutTransaction(t, handler, account, slodomain.SLOBindingRedirect)
	result := mustOrchestrateIDPFanout(t, handler, transaction, account)

	assert.NotNil(t, result)
	assert.Empty(t, result.Dispatches)
	assert.Empty(t, result.Failures)
	assert.Equal(t, slodomain.SLOStatusDone, transaction.Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_MaxParticipantsLimit(t *testing.T) {
	idpKey, _, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	cfg := &mockSAMLCfg{
		entityID:           "https://auth.example.com/saml/metadata",
		certificate:        string(idpCertPEM),
		key:                string(idpKeyPEM),
		redisPrefix:        "test:",
		sloMaxParticipants: 1,
		sps: []config.SAML2ServiceProvider{
			{
				EntityID: "https://sp-a.example.com/metadata",
				SLOURL:   "https://sp-a.example.com/saml/slo",
			},
			{
				EntityID: "https://sp-b.example.com/metadata",
				SLOURL:   "https://sp-b.example.com/saml/slo",
			},
		},
	}

	handler, mock := newSLOFanoutTestHandler(cfg)
	account := "frank@example.com"

	participantA := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-a.example.com/metadata",
		NameID:       "frank-name-id",
		SessionIndex: "session-a",
		AuthnInstant: time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
	}
	participantB := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-b.example.com/metadata",
		NameID:       "frank-name-id",
		SessionIndex: "session-b",
		AuthnInstant: time.Date(2026, time.March, 18, 12, 1, 0, 0, time.UTC),
	}

	mustExpectSLOParticipantSessions(t, mock, "test:", account, participantB, participantA)

	transaction := mustLocalDoneIDPFanoutTransaction(t, handler, account, slodomain.SLOBindingRedirect)
	result := mustOrchestrateIDPFanout(t, handler, transaction, account)

	if !assert.NotNil(t, result) {
		return
	}

	assertMaxParticipantsFanoutResult(t, result)
	assert.Equal(t, slodomain.SLOStatusFanoutRunning, transaction.Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// newSLOFanoutTestHandler creates a SAML handler backed by a Redis mock.
func newSLOFanoutTestHandler(cfg *mockSAMLCfg) (*SAMLHandler, redismock.ClientMock) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	return NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil), mock
}

// mustExpectSLOParticipantSessions registers Redis expectations for participant lookups.
func mustExpectSLOParticipantSessions(
	t *testing.T,
	mock redismock.ClientMock,
	redisPrefix string,
	account string,
	participants ...slodomain.ParticipantSession,
) {
	t.Helper()

	keys := make([]string, 0, len(participants))
	rawByKey := make(map[string]string, len(participants))

	for _, participant := range participants {
		key := sloTestParticipantKey(redisPrefix, account, participant.SPEntityID)

		rawParticipant, err := json.Marshal(participant)
		if !assert.NoError(t, err) {
			return
		}

		keys = append(keys, key)
		rawByKey[key] = string(rawParticipant)
	}

	mock.ExpectSMembers(sloTestParticipantIndexKey(redisPrefix, account)).SetVal(keys)

	for _, key := range keys {
		mock.ExpectGet(key).SetVal(rawByKey[key])
	}
}

// mustLocalDoneIDPFanoutTransaction creates an IDP-initiated transaction ready for fanout.
func mustLocalDoneIDPFanoutTransaction(
	t *testing.T,
	handler *SAMLHandler,
	account string,
	binding slodomain.Binding,
) *slodomain.Transaction {
	t.Helper()

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, binding)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	if !assert.NoError(t, transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())) {
		t.FailNow()
	}

	return transaction
}

// mustOrchestrateIDPFanout runs IDP-initiated fanout and requires success.
func mustOrchestrateIDPFanout(
	t *testing.T,
	handler *SAMLHandler,
	transaction *slodomain.Transaction,
	account string,
) *sloFanoutResult {
	t.Helper()

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return result
}

// newRedirectSLOFanoutConfig builds the redirect fanout test configuration.
func newRedirectSLOFanoutConfig(idpCertPEM []byte, idpKeyPEM []byte) *mockSAMLCfg {
	return &mockSAMLCfg{
		entityID:    "https://auth.example.com/saml/metadata",
		certificate: string(idpCertPEM),
		key:         string(idpKeyPEM),
		redisPrefix: "test:",
		sps: []config.SAML2ServiceProvider{
			{EntityID: "https://sp-a.example.com/metadata", SLOURL: "https://sp-a.example.com/saml/slo"},
			{EntityID: "https://sp-b.example.com/metadata", SLOURL: "https://sp-b.example.com/saml/slo"},
		},
	}
}

// redirectSLOFanoutParticipants returns ordered participants for redirect fanout.
func redirectSLOFanoutParticipants(account string) (slodomain.ParticipantSession, slodomain.ParticipantSession, slodomain.ParticipantSession) {
	participantB := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-b.example.com/metadata",
		SessionIndex: "session-b",
		AuthnInstant: time.Date(2026, time.March, 18, 8, 30, 0, 0, time.UTC),
	}
	participantInvalid := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "not-an-absolute-url",
		NameID:       "alice@example.com",
		SessionIndex: "session-invalid",
		AuthnInstant: time.Date(2026, time.March, 18, 8, 40, 0, 0, time.UTC),
	}
	participantA := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-a.example.com/metadata",
		NameID:       "alice-name-id",
		SessionIndex: "session-a",
		AuthnInstant: time.Date(2026, time.March, 18, 8, 20, 0, 0, time.UTC),
	}

	return participantB, participantInvalid, participantA
}

// newBackChannelCaptureServer captures one back-channel form submission.
func newBackChannelCaptureServer(t *testing.T) (chan url.Values, *httptest.Server) {
	t.Helper()

	receivedForm := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			resp.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if err := req.ParseForm(); err != nil {
			resp.WriteHeader(http.StatusBadRequest)

			return
		}

		receivedForm <- req.PostForm

		resp.WriteHeader(http.StatusOK)
	}))

	return receivedForm, server
}

// newSLOBackChannelRedirectTestDelivery creates a minimal delivery for redirect policy tests.
func newSLOBackChannelRedirectTestDelivery(destination string) backChannelSLODelivery {
	handler := &SAMLHandler{deps: &deps.Deps{Cfg: &mockSAMLCfg{}}}

	return backChannelSLODelivery{
		Client:         handler.newBackChannelSLOHTTPClient(time.Second),
		FormBody:       url.Values{"SAMLRequest": {"request"}}.Encode(),
		Destination:    destination,
		RequestTimeout: time.Second,
		Attempts:       1,
	}
}

// newBackChannelSuccessSLOFanoutConfig builds config for successful back-channel fanout.
func newBackChannelSuccessSLOFanoutConfig(idpCertPEM []byte, idpKeyPEM []byte, serverURL string) *mockSAMLCfg {
	enabled := true

	return &mockSAMLCfg{
		entityID:              "https://auth.example.com/saml/metadata",
		certificate:           string(idpCertPEM),
		key:                   string(idpKeyPEM),
		redisPrefix:           "test:",
		sloBackChannelEnabled: &enabled,
		sloRequestTimeout:     2 * time.Second,
		sps: []config.SAML2ServiceProvider{
			{
				EntityID:          "https://sp-back.example.com/metadata",
				SLOURL:            "https://sp-back.example.com/saml/slo",
				SLOBackChannelURL: serverURL + "/saml/slo-back",
			},
		},
	}
}

// backChannelSuccessSLOParticipant returns the participant for back-channel fanout.
func backChannelSuccessSLOParticipant(account string) slodomain.ParticipantSession {
	return slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-back.example.com/metadata",
		NameID:       "carol-name-id",
		SessionIndex: "session-back",
		AuthnInstant: time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC),
	}
}

// assertRedirectFanoutDispatches validates redirect-binding fanout requests.
func assertRedirectFanoutDispatches(
	t *testing.T,
	dispatches []sloFanoutDispatch,
	transaction *slodomain.Transaction,
	idpCert *x509.Certificate,
	fallbackNameID string,
) {
	t.Helper()

	participantByEntity := map[string]slodomain.Participant{}
	for _, participant := range transaction.Participants {
		participantByEntity[participant.EntityID] = participant
	}

	for _, dispatch := range dispatches {
		assertRedirectFanoutDispatch(t, dispatch, transaction, participantByEntity, idpCert, fallbackNameID)
	}
}

// assertRedirectFanoutDispatch validates one redirect-binding fanout request.
func assertRedirectFanoutDispatch(
	t *testing.T,
	dispatch sloFanoutDispatch,
	transaction *slodomain.Transaction,
	participantByEntity map[string]slodomain.Participant,
	idpCert *x509.Certificate,
	fallbackNameID string,
) {
	t.Helper()

	parsedURL, err := url.Parse(dispatch.RedirectURL)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, transaction.TransactionID, parsedURL.Query().Get("RelayState"))
	assert.NotEmpty(t, parsedURL.Query().Get("SAMLRequest"))
	assert.NotEmpty(t, parsedURL.Query().Get("SigAlg"))
	assert.NotEmpty(t, parsedURL.Query().Get("Signature"))
	assert.NoError(t, validateRedirectLogoutRequestSignature(parsedURL.RawQuery, []*x509.Certificate{idpCert}))

	logoutRequest := mustDecodeRedirectLogoutRequest(t, parsedURL.Query().Get("SAMLRequest"))
	assert.Equal(t, participantByEntity[dispatch.Participant.EntityID].RequestID, logoutRequest.ID)
	assert.Equal(t, "https://auth.example.com/saml/metadata", logoutRequest.Issuer.Value)
	assertRedirectFanoutParticipant(t, dispatch.Participant.EntityID, logoutRequest, fallbackNameID)
}

// assertRedirectFanoutParticipant validates participant-specific redirect payload fields.
func assertRedirectFanoutParticipant(t *testing.T, entityID string, logoutRequest *saml.LogoutRequest, fallbackNameID string) {
	t.Helper()

	switch entityID {
	case "https://sp-a.example.com/metadata":
		assert.Equal(t, "alice-name-id", logoutRequest.NameID.Value)
		assert.Equal(t, "session-a", logoutRequest.SessionIndex.Value)
	case "https://sp-b.example.com/metadata":
		assert.Equal(t, fallbackNameID, logoutRequest.NameID.Value)
		assert.Equal(t, "session-b", logoutRequest.SessionIndex.Value)
	}
}

// assertPostFanoutDispatch validates a POST-binding fanout request.
func assertPostFanoutDispatch(
	t *testing.T,
	dispatch sloFanoutDispatch,
	transaction *slodomain.Transaction,
	idpCert *x509.Certificate,
	wantNameID string,
	wantSessionIndex string,
) {
	t.Helper()

	assert.Empty(t, dispatch.RedirectURL)
	assert.NotEmpty(t, dispatch.PostBody)

	rawRequestXML := mustDecodePostFanoutRequestXML(t, dispatch.PostBody, transaction.TransactionID)

	var logoutRequest saml.LogoutRequest
	if !assert.NoError(t, xml.Unmarshal(rawRequestXML, &logoutRequest)) {
		return
	}

	assert.NotNil(t, logoutRequest.Signature)
	assert.Equal(t, wantNameID, logoutRequest.NameID.Value)

	if assert.NotNil(t, logoutRequest.SessionIndex) {
		assert.Equal(t, wantSessionIndex, logoutRequest.SessionIndex.Value)
	}

	assert.Equal(t, dispatch.Participant.RequestID, logoutRequest.ID)
	assert.NoError(t, validateXMLLogoutRequestSignature(rawRequestXML, []*x509.Certificate{idpCert}))
}

// mustDecodePostFanoutRequestXML extracts and decodes POST-binding SAMLRequest XML.
func mustDecodePostFanoutRequestXML(t *testing.T, postBody string, transactionID string) []byte {
	t.Helper()

	postSAMLRequest := mustExtractHiddenFormValue(t, postBody, "SAMLRequest")
	postRelayState := mustExtractHiddenFormValue(t, postBody, "RelayState")
	assert.Equal(t, transactionID, postRelayState)

	rawRequestXML, err := base64.StdEncoding.DecodeString(postSAMLRequest)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return rawRequestXML
}

// assertBackChannelFanoutRequest validates the captured back-channel request.
func assertBackChannelFanoutRequest(
	t *testing.T,
	receivedForm <-chan url.Values,
	transaction *slodomain.Transaction,
	idpCert *x509.Certificate,
	wantNameID string,
	wantSessionIndex string,
) {
	t.Helper()

	var form url.Values
	select {
	case form = <-receivedForm:
	case <-time.After(2 * time.Second):
		t.Fatal("expected one back-channel SLO request")
	}

	assert.Equal(t, transaction.TransactionID, form.Get("RelayState"))

	rawRequestXML, err := base64.StdEncoding.DecodeString(form.Get("SAMLRequest"))
	if !assert.NoError(t, err) {
		return
	}

	var logoutRequest saml.LogoutRequest
	if !assert.NoError(t, xml.Unmarshal(rawRequestXML, &logoutRequest)) {
		return
	}

	assert.Equal(t, transaction.Participants[0].RequestID, logoutRequest.ID)
	assert.Equal(t, wantNameID, logoutRequest.NameID.Value)
	assert.Equal(t, wantSessionIndex, logoutRequest.SessionIndex.Value)
	assert.NoError(t, validateXMLLogoutRequestSignature(rawRequestXML, []*x509.Certificate{idpCert}))
}

// assertMaxParticipantsFanoutResult validates participant-limit fanout behavior.
func assertMaxParticipantsFanoutResult(t *testing.T, result *sloFanoutResult) {
	t.Helper()

	if !assert.Len(t, result.Dispatches, 1) {
		return
	}

	if !assert.Len(t, result.Failures, 1) {
		return
	}

	assert.Equal(t, "https://sp-a.example.com/metadata", result.Dispatches[0].Participant.EntityID)
	assert.Equal(t, "https://sp-b.example.com/metadata", result.Failures[0].EntityID)
	assert.ErrorContains(t, result.Failures[0].Err, "slo max participants limit reached")
}
