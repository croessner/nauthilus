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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
)

func TestSAMLHandler_validateInboundLogoutResponseSignature_Redirect(t *testing.T) {
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

	logoutResponse := mustBuildSignedLogoutResponse(
		t,
		spKey,
		spCert,
		spEntityID,
		destination,
		"id-request-1",
		dsig.RSASHA256SignatureMethod,
		saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	)

	validTarget := logoutResponse.Redirect("relay-state").String()
	tamperedTarget := mustMutateRedirectSAMLResponseTarget(
		t,
		validTarget,
		func(rawXML []byte) []byte {
			return bytes.Replace(rawXML, []byte("id-request-1"), []byte("id-request-2"), 1)
		},
	)

	testCases := []struct {
		name    string
		target  string
		wantErr string
	}{
		{
			name:   "valid XML signature",
			target: validTarget,
		},
		{
			name:    "tampered XML payload",
			target:  tamperedTarget,
			wantErr: "cannot validate LogoutResponse XML signature",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)

			message, err := routeSLOInboundMessage(req)
			if !assert.NoError(t, err) {
				return
			}

			_, err = handler.validateInboundLogoutResponseSignature(req, message)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestSAMLHandler_validateInboundLogoutResponseProtocol_FieldValidation(t *testing.T) {
	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{},
	}, nil)

	baseResponse := func() *saml.LogoutResponse {
		return &saml.LogoutResponse{
			ID:           "id-response-protocol",
			InResponseTo: "id-request-protocol",
			Version:      "2.0",
			IssueInstant: saml.TimeNow().UTC(),
			Destination:  "https://auth.example.com/saml/slo",
			Issuer: &saml.Issuer{
				Value: "https://sp.example.com/saml/metadata",
			},
			Status: saml.Status{
				StatusCode: saml.StatusCode{
					Value: saml.StatusSuccess,
				},
			},
		}
	}

	testCases := []struct {
		name    string
		mutate  func(response *saml.LogoutResponse)
		wantErr string
	}{
		{
			name: "missing response id",
			mutate: func(response *saml.LogoutResponse) {
				response.ID = ""
			},
			wantErr: "logout response id is missing",
		},
		{
			name: "missing in response to",
			mutate: func(response *saml.LogoutResponse) {
				response.InResponseTo = ""
			},
			wantErr: "logout response InResponseTo is missing",
		},
		{
			name: "wrong destination",
			mutate: func(response *saml.LogoutResponse) {
				response.Destination = "https://evil.example.org/saml/slo"
			},
			wantErr: "does not match expected endpoint",
		},
		{
			name: "missing issue instant",
			mutate: func(response *saml.LogoutResponse) {
				response.IssueInstant = time.Time{}
			},
			wantErr: "IssueInstant is missing",
		},
		{
			name: "issue instant too old",
			mutate: func(response *saml.LogoutResponse) {
				response.IssueInstant = saml.TimeNow().UTC().Add(-(saml.MaxIssueDelay + time.Second))
			},
			wantErr: "IssueInstant is too old",
		},
		{
			name: "missing status code",
			mutate: func(response *saml.LogoutResponse) {
				response.Status.StatusCode.Value = ""
			},
			wantErr: "logout response StatusCode is missing",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			response := baseResponse()
			tc.mutate(response)

			err := handler.validateInboundLogoutResponseProtocol(response)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestSAMLHandler_applySLOFanoutLogoutResponse_AggregatesFinalStatus(t *testing.T) {
	const (
		redisPrefix   = "test:"
		transactionID = "tx-slo-aggregate"
		requestID     = "id-slo-request-aggregate"
		entityID      = "https://sp.example.com/saml/metadata"
	)

	baseTransaction := func(t *testing.T) slodomain.SLOTransaction {
		t.Helper()

		now := time.Date(2026, time.March, 19, 9, 0, 0, 0, time.UTC)
		tx, err := slodomain.NewTransaction(
			transactionID,
			"id-root-request",
			slodomain.SLODirectionIDPInitiated,
			slodomain.SLOBindingRedirect,
			now,
		)
		if err != nil {
			t.Fatalf("cannot create slo transaction: %v", err)
		}

		if err = tx.TransitionTo(slodomain.SLOStatusValidated, now); err != nil {
			t.Fatalf("cannot transition to validated: %v", err)
		}

		if err = tx.TransitionTo(slodomain.SLOStatusLocalDone, now); err != nil {
			t.Fatalf("cannot transition to local_done: %v", err)
		}

		if err = tx.TransitionTo(slodomain.SLOStatusFanoutRunning, now); err != nil {
			t.Fatalf("cannot transition to fanout_running: %v", err)
		}

		tx.Participants = []slodomain.SLOParticipant{
			{
				EntityID:  entityID,
				RequestID: requestID,
				Binding:   slodomain.SLOBindingRedirect,
			},
		}

		return *tx
	}

	testCases := []struct {
		name           string
		preSuccess     int
		preFailure     int
		responseStatus string
		wantStatus     slodomain.SLOStatus
		wantSuccess    int
		wantFailure    int
	}{
		{
			name:           "done when all successful",
			preSuccess:     0,
			preFailure:     0,
			responseStatus: saml.StatusSuccess,
			wantStatus:     slodomain.SLOStatusDone,
			wantSuccess:    1,
			wantFailure:    0,
		},
		{
			name:           "partial when planning already failed",
			preSuccess:     0,
			preFailure:     1,
			responseStatus: saml.StatusSuccess,
			wantStatus:     slodomain.SLOStatusPartial,
			wantSuccess:    1,
			wantFailure:    1,
		},
		{
			name:           "failed when no successful participant remains",
			preSuccess:     0,
			preFailure:     1,
			responseStatus: saml.StatusResponder,
			wantStatus:     slodomain.SLOStatusFailed,
			wantSuccess:    0,
			wantFailure:    2,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			redisClient := rediscli.NewTestClient(db)

			handler := NewSAMLHandler(&deps.Deps{
				Cfg: &mockSAMLCfg{
					redisPrefix: redisPrefix,
				},
				Redis: redisClient,
			}, nil)

			transaction := baseTransaction(t)
			state := &sloFanoutTransactionState{
				Transaction: transaction,
				Pending: map[string]slodomain.SLOParticipant{
					requestID: {
						EntityID:  entityID,
						RequestID: requestID,
						Binding:   slodomain.SLOBindingRedirect,
					},
				},
				Outcomes:        map[string]sloFanoutParticipantOutcome{},
				PreSuccessCount: tc.preSuccess,
				PreFailureCount: tc.preFailure,
				UpdatedAt:       time.Date(2026, time.March, 19, 9, 5, 0, 0, time.UTC),
			}

			rawState, err := json.Marshal(state)
			if !assert.NoError(t, err) {
				return
			}

			requestKey := handler.sloFanoutRequestKey(requestID)
			transactionKey := handler.sloFanoutStateKey(transactionID)

			mock.ExpectGet(requestKey).SetVal(transactionID)
			mock.ExpectGet(transactionKey).SetVal(string(rawState))
			mock.Regexp().ExpectSet(transactionKey, `.+`, time.Hour).SetVal("OK")
			mock.ExpectDel(requestKey).SetVal(1)

			logoutResponse := &saml.LogoutResponse{
				ID:           "id-response-aggregate",
				InResponseTo: requestID,
				IssueInstant: saml.TimeNow().UTC(),
				Issuer: &saml.Issuer{
					Value: entityID,
				},
				Status: saml.Status{
					StatusCode: saml.StatusCode{
						Value: tc.responseStatus,
					},
				},
			}

			aggregation, err := handler.applySLOFanoutLogoutResponse(t.Context(), logoutResponse, transactionID)
			if !assert.NoError(t, err) {
				return
			}

			if !assert.NotNil(t, aggregation) {
				return
			}

			assert.Equal(t, tc.wantStatus, aggregation.Status)
			assert.Equal(t, tc.wantSuccess, aggregation.SuccessCount)
			assert.Equal(t, tc.wantFailure, aggregation.FailureCount)
			assert.Equal(t, 0, aggregation.PendingCount)
			assert.True(t, aggregation.Final)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestSAMLHandler_storeSLOFanoutTransactionState_PersistsPendingRequests(t *testing.T) {
	const (
		redisPrefix   = "test:"
		transactionID = "tx-slo-store"
		requestID     = "id-slo-request-store"
		entityID      = "https://sp.example.com/saml/metadata"
	)

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			redisPrefix: redisPrefix,
		},
		Redis: redisClient,
	}, nil)

	now := time.Date(2026, time.March, 19, 11, 0, 0, 0, time.UTC)
	tx, err := slodomain.NewTransaction(
		transactionID,
		"id-root-store",
		slodomain.SLODirectionIDPInitiated,
		slodomain.SLOBindingRedirect,
		now,
	)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.NoError(t, tx.TransitionTo(slodomain.SLOStatusValidated, now)) {
		return
	}

	if !assert.NoError(t, tx.TransitionTo(slodomain.SLOStatusLocalDone, now)) {
		return
	}

	if !assert.NoError(t, tx.TransitionTo(slodomain.SLOStatusFanoutRunning, now)) {
		return
	}

	tx.Participants = []slodomain.SLOParticipant{
		{
			EntityID:  entityID,
			RequestID: requestID,
			Binding:   slodomain.SLOBindingRedirect,
		},
	}

	result := &sloFanoutResult{
		Dispatches: []sloFanoutDispatch{
			{
				Participant: tx.Participants[0],
			},
		},
	}

	transactionKey := handler.sloFanoutStateKey(transactionID)
	requestKey := handler.sloFanoutRequestKey(requestID)

	mock.Regexp().ExpectSet(transactionKey, `.+`, time.Hour).SetVal("OK")
	mock.ExpectSet(requestKey, transactionID, time.Hour).SetVal("OK")

	err = handler.storeSLOFanoutTransactionState(t.Context(), tx, result)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSAMLHandler_SLO_LogoutResponse_CompletesFanout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const (
		redisPrefix   = "test:"
		transactionID = "tx-slo-end-to-end"
		requestID     = "id-slo-request-end-to-end"
		entityID      = "https://sp.example.com/saml/metadata"
		destination   = "https://auth.example.com/saml/slo"
	)

	spKey, spCert, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			redisPrefix: redisPrefix,
			sps: []config.SAML2ServiceProvider{
				{
					EntityID: entityID,
					ACSURL:   "https://sp.example.com/saml/acs",
					Cert:     string(spCertPEM),
				},
			},
		},
		Logger: slog.Default(),
		Redis:  redisClient,
	}, nil)

	now := time.Date(2026, time.March, 19, 10, 0, 0, 0, time.UTC)
	tx, err := slodomain.NewTransaction(
		transactionID,
		"id-root-end-to-end",
		slodomain.SLODirectionIDPInitiated,
		slodomain.SLOBindingRedirect,
		now,
	)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.NoError(t, tx.TransitionTo(slodomain.SLOStatusValidated, now)) {
		return
	}

	if !assert.NoError(t, tx.TransitionTo(slodomain.SLOStatusLocalDone, now)) {
		return
	}

	if !assert.NoError(t, tx.TransitionTo(slodomain.SLOStatusFanoutRunning, now)) {
		return
	}

	tx.Participants = []slodomain.SLOParticipant{
		{
			EntityID:  entityID,
			RequestID: requestID,
			Binding:   slodomain.SLOBindingRedirect,
		},
	}

	state := &sloFanoutTransactionState{
		Transaction: *tx,
		Pending: map[string]slodomain.SLOParticipant{
			requestID: tx.Participants[0],
		},
		Outcomes:        map[string]sloFanoutParticipantOutcome{},
		PreSuccessCount: 0,
		PreFailureCount: 0,
		UpdatedAt:       now,
	}

	rawState, err := json.Marshal(state)
	if !assert.NoError(t, err) {
		return
	}

	requestKey := handler.sloFanoutRequestKey(requestID)
	transactionKey := handler.sloFanoutStateKey(transactionID)

	mock.ExpectGet(requestKey).SetVal(transactionID)
	mock.ExpectGet(transactionKey).SetVal(string(rawState))
	mock.Regexp().ExpectSet(transactionKey, `.+`, time.Hour).SetVal("OK")
	mock.ExpectDel(requestKey).SetVal(1)

	logoutResponse := mustBuildSignedLogoutResponse(
		t,
		spKey,
		spCert,
		entityID,
		destination,
		requestID,
		dsig.RSASHA256SignatureMethod,
		saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	)

	target := logoutResponse.Redirect(transactionID).String()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, target, nil)

	handler.SLO(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "SAML LogoutResponse processed")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func mustBuildSignedLogoutResponse(
	t *testing.T,
	spKey *rsa.PrivateKey,
	spCert *x509.Certificate,
	issuer string,
	destination string,
	inResponseTo string,
	signatureMethod string,
	status saml.Status,
) *saml.LogoutResponse {
	t.Helper()

	if strings.TrimSpace(status.StatusCode.Value) == "" {
		status = saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		}
	}

	logoutResponse := &saml.LogoutResponse{
		ID:           "id-response-" + strings.ReplaceAll(inResponseTo, " ", "-"),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: saml.TimeNow().UTC(),
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: samlEntityIssuerFormat,
			Value:  issuer,
		},
		Status: status,
	}

	signingSP := &saml.ServiceProvider{
		Key:             spKey,
		Certificate:     spCert,
		SignatureMethod: signatureMethod,
	}

	if err := signingSP.SignLogoutResponse(logoutResponse); err != nil {
		t.Fatalf("failed to sign logout response: %v", err)
	}

	return logoutResponse
}

func mustMutateRedirectSAMLResponseTarget(t *testing.T, target string, mutate func(rawXML []byte) []byte) string {
	t.Helper()

	parsedTarget, err := url.Parse(target)
	if err != nil {
		t.Fatalf("failed to parse redirect target: %v", err)
	}

	query := parsedTarget.Query()
	rawPayloadB64 := query.Get("SAMLResponse")
	if rawPayloadB64 == "" {
		t.Fatal("redirect target is missing SAMLResponse")
	}

	rawPayload, err := base64.StdEncoding.DecodeString(rawPayloadB64)
	if err != nil {
		t.Fatalf("failed to decode SAMLResponse payload: %v", err)
	}

	reader := flate.NewReader(bytes.NewReader(rawPayload))
	xmlPayload, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("failed to inflate SAMLResponse payload: %v", err)
	}

	xmlPayload = mutate(xmlPayload)

	var encoded bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &encoded)
	deflater, err := flate.NewWriter(encoder, 9)
	if err != nil {
		t.Fatalf("failed to create deflater: %v", err)
	}

	if _, err = deflater.Write(xmlPayload); err != nil {
		t.Fatalf("failed to deflate mutated XML payload: %v", err)
	}

	if err = deflater.Close(); err != nil {
		t.Fatalf("failed to close deflater: %v", err)
	}

	if err = encoder.Close(); err != nil {
		t.Fatalf("failed to close base64 encoder: %v", err)
	}

	query.Set("SAMLResponse", encoded.String())
	parsedTarget.RawQuery = query.Encode()

	return parsedTarget.String()
}
