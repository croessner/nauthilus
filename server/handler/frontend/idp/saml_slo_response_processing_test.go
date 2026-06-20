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
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/croessner/nauthilus/v3/server/rediscli"
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

	testCases := []sloRedirectSignatureCase{
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

	assertSLOInboundRedirectSignatureCases(t, testCases, func(req *http.Request, message *sloInboundMessage) error {
		_, err := handler.validateInboundLogoutResponseSignature(req, message)

		return err
	})
}

func TestSAMLHandler_validateInboundLogoutResponseSignature_Redirect_OptionalUnsigned(t *testing.T) {
	spEntityID := "https://sp.example.com/saml/metadata"
	unsigned := false

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			sps: []config.SAML2ServiceProvider{
				{
					EntityID:              spEntityID,
					ACSURL:                "https://sp.example.com/saml/acs",
					LogoutResponsesSigned: &unsigned,
				},
			},
		},
		Logger: slog.Default(),
	}, nil)

	target := (&saml.LogoutResponse{
		ID:           "id-response-unsigned",
		InResponseTo: "id-request-unsigned",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Value: spEntityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
	}).Redirect("relay-state").String()

	req := httptest.NewRequest(http.MethodGet, target, nil)

	message, err := routeSLOInboundMessage(req)
	if !assert.NoError(t, err) {
		return
	}

	_, err = handler.validateInboundLogoutResponseSignature(req, message)
	assert.NoError(t, err)
}

func TestSAMLHandler_validateInboundLogoutResponseSignature_Redirect_DefaultUnsigned(t *testing.T) {
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

	target := (&saml.LogoutResponse{
		ID:           "id-response-default-unsigned",
		InResponseTo: "id-request-default-unsigned",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Value: spEntityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
	}).Redirect("relay-state").String()

	req := httptest.NewRequest(http.MethodGet, target, nil)

	message, err := routeSLOInboundMessage(req)
	if !assert.NoError(t, err) {
		return
	}

	_, err = handler.validateInboundLogoutResponseSignature(req, message)
	assert.NoError(t, err)
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

	for _, tc := range logoutResponseProtocolFieldCases() {
		t.Run(tc.name, func(t *testing.T) {
			response := baseResponse()
			tc.mutate(response)

			err := handler.validateInboundLogoutResponseProtocol(response)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

type logoutResponseProtocolFieldCase struct {
	name    string
	mutate  func(response *saml.LogoutResponse)
	wantErr string
}

// logoutResponseProtocolFieldCases returns field-validation mutations for LogoutResponse.
func logoutResponseProtocolFieldCases() []logoutResponseProtocolFieldCase {
	return []logoutResponseProtocolFieldCase{
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
}

func TestSAMLHandler_applySLOFanoutLogoutResponse_AggregatesFinalStatus(t *testing.T) {
	const (
		redisPrefix   = "test:"
		transactionID = "tx-slo-aggregate"
		requestID     = "id-slo-request-aggregate"
		entityID      = "https://sp.example.com/saml/metadata"
	)

	for _, tc := range sloFanoutAggregationFinalStatusCases() {
		t.Run(tc.name, func(t *testing.T) {
			handler, mock := newSLOFanoutResponseTestHandler(redisPrefix)
			transaction := mustIDPFanoutRunningTransaction(t, transactionID, "id-root-request", slodomain.SLOBindingRedirect, entityID, requestID)
			state := newPendingSLOFanoutState(transaction, requestID, time.Date(2026, time.March, 19, 9, 5, 0, 0, time.UTC), tc.preSuccess, tc.preFailure)
			mustExpectSLOFanoutStateUpdate(t, handler, mock, transactionID, requestID, state, true)
			logoutResponse := newSLOFanoutTestLogoutResponse("id-response-aggregate", requestID, entityID, tc.responseStatus)

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

type sloFanoutAggregationFinalStatusCase struct {
	name           string
	preSuccess     int
	preFailure     int
	responseStatus string
	wantStatus     slodomain.Status
	wantSuccess    int
	wantFailure    int
}

// sloFanoutAggregationFinalStatusCases returns terminal aggregation status cases.
func sloFanoutAggregationFinalStatusCases() []sloFanoutAggregationFinalStatusCase {
	return []sloFanoutAggregationFinalStatusCase{
		{
			name:           "done when all successful",
			responseStatus: saml.StatusSuccess,
			wantStatus:     slodomain.SLOStatusDone,
			wantSuccess:    1,
		},
		{
			name:           "partial when planning already failed",
			preFailure:     1,
			responseStatus: saml.StatusSuccess,
			wantStatus:     slodomain.SLOStatusPartial,
			wantSuccess:    1,
			wantFailure:    1,
		},
		{
			name:           "failed when no successful participant remains",
			preFailure:     1,
			responseStatus: saml.StatusResponder,
			wantStatus:     slodomain.SLOStatusFailed,
			wantFailure:    2,
		},
	}
}

func TestSAMLHandler_storeSLOFanoutTransactionState_PersistsPendingRequests(t *testing.T) {
	const (
		redisPrefix   = "test:"
		transactionID = "tx-slo-store"
		requestID     = "id-slo-request-store"
		entityID      = "https://sp.example.com/saml/metadata"
	)

	handler, mock := newSLOFanoutResponseTestHandler(redisPrefix)
	tx := mustIDPFanoutRunningTransaction(t, transactionID, "id-root-store", slodomain.SLOBindingRedirect, entityID, requestID)

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

	err := handler.storeSLOFanoutTransactionState(t.Context(), tx, result)
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

	handler, mock := newSLOFanoutResponseTestHandler(redisPrefix, config.SAML2ServiceProvider{
		EntityID: entityID,
		ACSURL:   "https://sp.example.com/saml/acs",
		Cert:     string(spCertPEM),
	})
	tx := mustIDPFanoutRunningTransaction(t, transactionID, "id-root-end-to-end", slodomain.SLOBindingRedirect, entityID, requestID)
	state := newPendingSLOFanoutState(tx, requestID, time.Date(2026, time.March, 19, 10, 0, 0, 0, time.UTC), 0, 0)
	mustExpectSLOFanoutStateUpdate(t, handler, mock, transactionID, requestID, state, true)

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

// newSLOFanoutResponseTestHandler creates a SAML handler and Redis mock for fanout response tests.
func newSLOFanoutResponseTestHandler(
	redisPrefix string,
	serviceProviders ...config.SAML2ServiceProvider,
) (*SAMLHandler, redismock.ClientMock) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	return NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{
			redisPrefix: redisPrefix,
			sps:         serviceProviders,
		},
		Logger: slog.Default(),
		Redis:  redisClient,
	}, nil), mock
}

// mustIDPFanoutRunningTransaction creates a transaction in fanout_running state.
func mustIDPFanoutRunningTransaction(
	t *testing.T,
	transactionID string,
	rootRequestID string,
	binding slodomain.Binding,
	entityID string,
	requestID string,
) *slodomain.Transaction {
	t.Helper()

	now := time.Date(2026, time.March, 19, 9, 0, 0, 0, time.UTC)

	tx, err := slodomain.NewTransaction(transactionID, rootRequestID, slodomain.SLODirectionIDPInitiated, binding, now)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	for _, status := range []slodomain.Status{
		slodomain.SLOStatusValidated,
		slodomain.SLOStatusLocalDone,
		slodomain.SLOStatusFanoutRunning,
	} {
		if !assert.NoError(t, tx.TransitionTo(status, now)) {
			t.FailNow()
		}
	}

	tx.Participants = []slodomain.Participant{{
		EntityID:  entityID,
		RequestID: requestID,
		Binding:   binding,
	}}

	return tx
}

// newPendingSLOFanoutState creates persisted fanout state with one pending request.
func newPendingSLOFanoutState(
	transaction *slodomain.Transaction,
	requestID string,
	updatedAt time.Time,
	preSuccess int,
	preFailure int,
) *sloFanoutTransactionState {
	return &sloFanoutTransactionState{
		Transaction: *transaction,
		Pending: map[string]slodomain.Participant{
			requestID: transaction.Participants[0],
		},
		Outcomes:        map[string]sloFanoutParticipantOutcome{},
		PreSuccessCount: preSuccess,
		PreFailureCount: preFailure,
		UpdatedAt:       updatedAt,
	}
}

// mustExpectSLOFanoutStateUpdate registers Redis expectations for loading and updating fanout state.
func mustExpectSLOFanoutStateUpdate(
	t *testing.T,
	handler *SAMLHandler,
	mock redismock.ClientMock,
	transactionID string,
	requestID string,
	state *sloFanoutTransactionState,
	final bool,
) {
	t.Helper()

	rawState, err := json.Marshal(state)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	requestKey := handler.sloFanoutRequestKey(requestID)
	transactionKey := handler.sloFanoutStateKey(transactionID)

	mock.ExpectGet(requestKey).SetVal(transactionID)
	mock.ExpectGet(transactionKey).SetVal(string(rawState))
	mock.Regexp().ExpectSet(transactionKey, `.+`, time.Hour).SetVal("OK")
	mock.ExpectDel(requestKey).SetVal(1)

	if final {
		return
	}
}

// newSLOFanoutTestLogoutResponse builds an unsigned LogoutResponse for state aggregation tests.
func newSLOFanoutTestLogoutResponse(responseID, requestID, entityID, responseStatus string) *saml.LogoutResponse {
	return &saml.LogoutResponse{
		ID:           responseID,
		InResponseTo: requestID,
		IssueInstant: saml.TimeNow().UTC(),
		Issuer: &saml.Issuer{
			Value: entityID,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: responseStatus,
			},
		},
	}
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
