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
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_Redirect(t *testing.T) {
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	cfg := &mockSAMLCfg{
		entityID:    "https://auth.example.com/saml/metadata",
		certificate: string(idpCertPEM),
		key:         string(idpKeyPEM),
		redisPrefix: "test:",
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

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	account := "alice@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)

	participantB := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-b.example.com/metadata",
		NameID:       "",
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

	keyB := sloTestParticipantKey("test:", account, participantB.SPEntityID)
	keyInvalid := sloTestParticipantKey("test:", account, participantInvalid.SPEntityID)
	keyA := sloTestParticipantKey("test:", account, participantA.SPEntityID)

	rawB, err := json.Marshal(participantB)
	if !assert.NoError(t, err) {
		return
	}

	rawInvalid, err := json.Marshal(participantInvalid)
	if !assert.NoError(t, err) {
		return
	}

	rawA, err := json.Marshal(participantA)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{keyB, keyInvalid, keyA})
	mock.ExpectGet(keyB).SetVal(string(rawB))
	mock.ExpectGet(keyInvalid).SetVal(string(rawInvalid))
	mock.ExpectGet(keyA).SetVal(string(rawA))

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		return
	}

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

	participantByEntity := map[string]slodomain.SLOParticipant{}
	for _, participant := range transaction.Participants {
		participantByEntity[participant.EntityID] = participant
	}

	for _, dispatch := range result.Dispatches {
		parsedURL, parseErr := url.Parse(dispatch.RedirectURL)
		if !assert.NoError(t, parseErr) {
			continue
		}

		assert.Equal(t, transaction.TransactionID, parsedURL.Query().Get("RelayState"))
		assert.NotEmpty(t, parsedURL.Query().Get("SAMLRequest"))
		assert.NotEmpty(t, parsedURL.Query().Get("SigAlg"))
		assert.NotEmpty(t, parsedURL.Query().Get("Signature"))
		assert.NoError(t, validateRedirectLogoutRequestSignature(parsedURL.RawQuery, []*x509.Certificate{idpCert}))

		logoutRequest := mustDecodeRedirectLogoutRequest(t, parsedURL.Query().Get("SAMLRequest"))
		assert.Equal(t, participantByEntity[dispatch.Participant.EntityID].RequestID, logoutRequest.ID)
		assert.Equal(t, "https://auth.example.com/saml/metadata", logoutRequest.Issuer.Value)

		switch dispatch.Participant.EntityID {
		case "https://sp-a.example.com/metadata":
			assert.Equal(t, "alice-name-id", logoutRequest.NameID.Value)
			assert.Equal(t, "session-a", logoutRequest.SessionIndex.Value)
		case "https://sp-b.example.com/metadata":
			assert.Equal(t, account, logoutRequest.NameID.Value)
			assert.Equal(t, "session-b", logoutRequest.SessionIndex.Value)
		}
	}

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

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	account := "bob@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)
	participant := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-post.example.com/metadata",
		NameID:       "bob-name-id",
		SessionIndex: "session-post",
		AuthnInstant: time.Date(2026, time.March, 18, 9, 0, 0, 0, time.UTC),
	}
	participantKey := sloTestParticipantKey("test:", account, participant.SPEntityID)
	rawParticipant, err := json.Marshal(participant)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectGet(participantKey).SetVal(string(rawParticipant))

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingPost)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.NotNil(t, result) {
		return
	}

	if !assert.Len(t, result.Dispatches, 1) {
		return
	}

	dispatch := result.Dispatches[0]
	assert.Empty(t, dispatch.RedirectURL)
	assert.NotEmpty(t, dispatch.PostBody)
	assert.Equal(t, slodomain.SLOStatusFanoutRunning, transaction.Status)

	postSAMLRequest := mustExtractHiddenFormValue(t, dispatch.PostBody, "SAMLRequest")
	postRelayState := mustExtractHiddenFormValue(t, dispatch.PostBody, "RelayState")
	assert.Equal(t, transaction.TransactionID, postRelayState)

	rawRequestXML, err := base64.StdEncoding.DecodeString(postSAMLRequest)
	if !assert.NoError(t, err) {
		return
	}

	var logoutRequest saml.LogoutRequest
	if !assert.NoError(t, xml.Unmarshal(rawRequestXML, &logoutRequest)) {
		return
	}

	assert.NotNil(t, logoutRequest.Signature)
	assert.Equal(t, "bob-name-id", logoutRequest.NameID.Value)
	if assert.NotNil(t, logoutRequest.SessionIndex) {
		assert.Equal(t, "session-post", logoutRequest.SessionIndex.Value)
	}
	assert.Equal(t, dispatch.Participant.RequestID, logoutRequest.ID)
	assert.NoError(t, validateXMLLogoutRequestSignature(rawRequestXML, []*x509.Certificate{idpCert}))
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

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	account := "nobody@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)
	mock.ExpectSMembers(indexKey).SetVal(nil)

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		return
	}

	assert.NotNil(t, result)
	assert.Empty(t, result.Dispatches)
	assert.Empty(t, result.Failures)
	assert.Equal(t, slodomain.SLOStatusDone, transaction.Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_BackChannelSuccess(t *testing.T) {
	idpKey, idpCert, idpCertPEM := mustGenerateRSACertificate(t, "idp.example.com")
	idpKeyPEM := mustEncodeRSAPrivateKeyPEM(t, idpKey)

	receivedForm := make(chan url.Values, 1)
	backChannelServer := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
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
	defer backChannelServer.Close()

	enabled := true
	cfg := &mockSAMLCfg{
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
				SLOBackChannelURL: backChannelServer.URL + "/saml/slo-back",
			},
		},
	}

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	account := "carol@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)
	participant := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-back.example.com/metadata",
		NameID:       "carol-name-id",
		SessionIndex: "session-back",
		AuthnInstant: time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC),
	}
	participantKey := sloTestParticipantKey("test:", account, participant.SPEntityID)
	rawParticipant, err := json.Marshal(participant)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectGet(participantKey).SetVal(string(rawParticipant))

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		return
	}

	assert.NotNil(t, result)
	assert.Empty(t, result.Dispatches)
	assert.Empty(t, result.Failures)
	assert.Equal(t, slodomain.SLOStatusDone, transaction.Status)
	if !assert.Len(t, transaction.Participants, 1) {
		return
	}

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
	assert.Equal(t, "carol-name-id", logoutRequest.NameID.Value)
	assert.Equal(t, "session-back", logoutRequest.SessionIndex.Value)
	assert.NoError(t, validateXMLLogoutRequestSignature(rawRequestXML, []*x509.Certificate{idpCert}))
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

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	account := "dave@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)
	participant := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-fallback.example.com/metadata",
		NameID:       "dave-name-id",
		SessionIndex: "session-fallback",
		AuthnInstant: time.Date(2026, time.March, 18, 11, 0, 0, 0, time.UTC),
	}
	participantKey := sloTestParticipantKey("test:", account, participant.SPEntityID)
	rawParticipant, err := json.Marshal(participant)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectGet(participantKey).SetVal(string(rawParticipant))

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		return
	}

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

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	account := "erin@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)
	participant := slodomain.ParticipantSession{
		Account:      account,
		SPEntityID:   "https://sp-erin.example.com/metadata",
		NameID:       "erin-name-id",
		SessionIndex: "session-erin",
		AuthnInstant: time.Date(2026, time.March, 18, 11, 10, 0, 0, time.UTC),
	}
	participantKey := sloTestParticipantKey("test:", account, participant.SPEntityID)
	rawParticipant, err := json.Marshal(participant)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{participantKey})
	mock.ExpectGet(participantKey).SetVal(string(rawParticipant))

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		return
	}

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

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:   cfg,
		Redis: redisClient,
	}, nil)

	account := "frank@example.com"
	indexKey := sloTestParticipantIndexKey("test:", account)

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

	keyA := sloTestParticipantKey("test:", account, participantA.SPEntityID)
	keyB := sloTestParticipantKey("test:", account, participantB.SPEntityID)
	rawA, err := json.Marshal(participantA)
	if !assert.NoError(t, err) {
		return
	}

	rawB, err := json.Marshal(participantB)
	if !assert.NoError(t, err) {
		return
	}

	mock.ExpectSMembers(indexKey).SetVal([]string{keyB, keyA})
	mock.ExpectGet(keyB).SetVal(string(rawB))
	mock.ExpectGet(keyA).SetVal(string(rawA))

	transaction, err := handler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if !assert.NoError(t, err) {
		return
	}

	err = transaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC())
	if !assert.NoError(t, err) {
		return
	}

	result, err := handler.orchestrateIDPInitiatedSLOFanout(t.Context(), transaction, account)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.NotNil(t, result) {
		return
	}

	if !assert.Len(t, result.Dispatches, 1) {
		return
	}

	if !assert.Len(t, result.Failures, 1) {
		return
	}

	assert.Equal(t, "https://sp-a.example.com/metadata", result.Dispatches[0].Participant.EntityID)
	assert.Equal(t, "https://sp-b.example.com/metadata", result.Failures[0].EntityID)
	assert.ErrorContains(t, result.Failures[0].Err, "slo max participants limit reached")
	assert.Equal(t, slodomain.SLOStatusFanoutRunning, transaction.Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func mustDecodeRedirectLogoutRequest(t *testing.T, encodedRequest string) *saml.LogoutRequest {
	t.Helper()

	rawDeflatedRequest, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		t.Fatalf("failed to decode redirect logout request base64: %v", err)
	}

	reader := flate.NewReader(bytes.NewReader(rawDeflatedRequest))
	defer reader.Close()

	requestXML, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to inflate redirect logout request: %v", err)
	}

	var request saml.LogoutRequest
	if err = xml.Unmarshal(requestXML, &request); err != nil {
		t.Fatalf("failed to unmarshal redirect logout request XML: %v", err)
	}

	return &request
}
