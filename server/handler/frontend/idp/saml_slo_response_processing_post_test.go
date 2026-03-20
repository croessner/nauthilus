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
	"encoding/json"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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

func TestSAMLHandler_SLO_LogoutResponse_CompletesFanout_POST(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const (
		redisPrefix   = "test:"
		transactionID = "tx-slo-end-to-end-post"
		requestID     = "id-slo-request-end-to-end-post"
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

	now := time.Date(2026, time.March, 19, 13, 0, 0, 0, time.UTC)
	tx, err := slodomain.NewTransaction(
		transactionID,
		"id-root-end-to-end-post",
		slodomain.SLODirectionIDPInitiated,
		slodomain.SLOBindingPost,
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
			Binding:   slodomain.SLOBindingPost,
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
		saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	)

	postForm := string(logoutResponse.Post(transactionID))

	responseMatch := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`).FindStringSubmatch(postForm)
	if !assert.Len(t, responseMatch, 2) {
		return
	}

	relayMatch := regexp.MustCompile(`name="RelayState" value="([^"]*)"`).FindStringSubmatch(postForm)
	if !assert.Len(t, relayMatch, 2) {
		return
	}

	form := url.Values{}
	form.Set("SAMLResponse", html.UnescapeString(responseMatch[1]))
	form.Set("RelayState", html.UnescapeString(relayMatch[1]))

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler.SLO(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "SAML LogoutResponse processed")
	assert.NoError(t, mock.ExpectationsWereMet())
}
