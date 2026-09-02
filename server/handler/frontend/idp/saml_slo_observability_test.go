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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/v4/server/idp/slo"
	"github.com/croessner/nauthilus/v4/server/middleware/limit"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func TestValidateSingleSLOParam_RejectsOversizedPayload(t *testing.T) {
	values := url.Values{
		"SAMLRequest": {strings.Repeat("a", sloMaxInboundMessageBytes+1)},
	}

	_, err := validateSingleSLOParam(values, "SAMLRequest")
	assert.Error(t, err)
	assert.ErrorIs(t, err, errSLOPayloadTooLarge)
}

func TestValidateSingleSLOParam_RejectsOversizedRelayState(t *testing.T) {
	boundary := strings.Repeat("a", sloMaxRelayStateBytes)
	value, err := validateSingleSLOParam(url.Values{"RelayState": {boundary}}, "RelayState")
	assert.NoError(t, err)
	assert.Equal(t, boundary, value)

	values := url.Values{
		"RelayState": {strings.Repeat("a", sloMaxRelayStateBytes+1)},
	}

	_, err = validateSingleSLOParam(values, "RelayState")
	assert.ErrorIs(t, err, errSLOPayloadTooLarge)
}

func TestSAMLSLOAdmissionBoundsBodyBeforeCheckpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewSAMLHandler(&deps.Deps{Cfg: &mockSAMLCfg{}}, nil)
	router := gin.New()
	router.POST(
		frontendSAMLLogoutPath,
		handler.sloAdmissionMiddleware(),
		handler.canonicalSAMLSLOMiddleware(nil),
		func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) },
	)

	for _, contentLength := range []int64{int64(sloMaxInboundBodyBytes + 1), -1} {
		body := bytes.Repeat([]byte("a"), sloMaxInboundBodyBytes+1)
		request := httptest.NewRequest(http.MethodPost, frontendSAMLLogoutPath, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.ContentLength = contentLength
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assert.Equal(t, http.StatusBadRequest, response.Code)
		assert.Contains(t, response.Body.String(), "Invalid SAML SLO payload")
	}
}

func TestSAMLSLOAdmissionRejectsRateLimitBeforeReadingBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewSAMLHandler(&deps.Deps{Cfg: &mockSAMLCfg{}}, nil)
	handler.sloRateLimiter = limit.NewIPRateLimiter(limit.Rate(0.01), 1)
	router := gin.New()
	router.POST(frontendSAMLLogoutPath, handler.sloAdmissionMiddleware(), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	first := httptest.NewRequest(http.MethodPost, frontendSAMLLogoutPath, strings.NewReader("SAMLRequest=opaque"))
	first.RemoteAddr = "203.0.113.21:12345"
	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, first)

	body := &countingSLOReader{reader: strings.NewReader("SAMLRequest=opaque")}
	second := httptest.NewRequest(http.MethodPost, frontendSAMLLogoutPath, body)
	second.RemoteAddr = first.RemoteAddr
	secondResponse := httptest.NewRecorder()
	router.ServeHTTP(secondResponse, second)

	assert.Equal(t, http.StatusTooManyRequests, secondResponse.Code)
	assert.Zero(t, body.reads)
}

type countingSLOReader struct {
	reader *strings.Reader
	reads  int
}

// Read records admission-layer request-body reads.
func (r *countingSLOReader) Read(buffer []byte) (int, error) {
	r.reads++

	return r.reader.Read(buffer)
}

func TestSAMLHandler_SLO_RateLimitAbuseGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewSAMLHandler(&deps.Deps{
		Cfg: &mockSAMLCfg{},
	}, nil)
	handler.sloRateLimiter = limit.NewIPRateLimiter(limit.Rate(0.01), 1)

	makeRequest := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/saml/slo", nil)
		req.RemoteAddr = "203.0.113.20:12345"
		ctx.Request = req

		handler.SLO(ctx)

		return w
	}

	first := makeRequest()
	assert.Equal(t, http.StatusBadRequest, first.Code)
	assert.Contains(t, first.Body.String(), "Invalid SAML SLO payload")

	second := makeRequest()
	assert.Equal(t, http.StatusTooManyRequests, second.Code)
	assert.Contains(t, second.Body.String(), "rate limit exceeded")
}

func TestSLOObservabilityMetrics(t *testing.T) {
	const (
		outcomeLabel = "test_observe"
		stageLabel   = "test_stage"
		reasonLabel  = "test_reason"
	)

	beforeRequests := testutil.ToFloat64(
		sloRequestsTotal.WithLabelValues("redirect", "logout_request", outcomeLabel),
	)
	beforeValidation := testutil.ToFloat64(
		sloValidationErrorsTotal.WithLabelValues("redirect", "logout_request", stageLabel),
	)
	beforeAbuse := testutil.ToFloat64(
		sloAbuseRejectionsTotal.WithLabelValues(reasonLabel, "redirect"),
	)
	beforeTerminal := testutil.ToFloat64(
		sloTerminalStatusTotal.WithLabelValues("sp_initiated", "partial"),
	)
	beforeHistogram := sloDurationSampleCount(t, "redirect", "logout_request", outcomeLabel)

	observeSLORequest(slodomain.SLOBindingRedirect, sloMessageTypeRequest, outcomeLabel, 25*time.Millisecond)
	recordSLOValidationError(stageLabel, sloMessageTypeRequest, slodomain.SLOBindingRedirect)
	recordSLOAbuseRejection(reasonLabel, slodomain.SLOBindingRedirect)
	recordSLOTerminalStatus(slodomain.SLODirectionSPInitiated, slodomain.SLOStatusPartial)

	afterRequests := testutil.ToFloat64(
		sloRequestsTotal.WithLabelValues("redirect", "logout_request", outcomeLabel),
	)
	afterValidation := testutil.ToFloat64(
		sloValidationErrorsTotal.WithLabelValues("redirect", "logout_request", stageLabel),
	)
	afterAbuse := testutil.ToFloat64(
		sloAbuseRejectionsTotal.WithLabelValues(reasonLabel, "redirect"),
	)
	afterTerminal := testutil.ToFloat64(
		sloTerminalStatusTotal.WithLabelValues("sp_initiated", "partial"),
	)
	afterHistogram := sloDurationSampleCount(t, "redirect", "logout_request", outcomeLabel)

	assert.Equal(t, beforeRequests+1, afterRequests)
	assert.Equal(t, beforeValidation+1, afterValidation)
	assert.Equal(t, beforeAbuse+1, afterAbuse)
	assert.Equal(t, beforeTerminal+1, afterTerminal)
	assert.Equal(t, beforeHistogram+1, afterHistogram)
}

func TestSLOTerminalStatusFromCleanup(t *testing.T) {
	assert.Equal(t, slodomain.SLOStatusDone, sloTerminalStatusFromCleanup(sloLocalCleanupResult{}))
	assert.Equal(
		t,
		slodomain.SLOStatusFailed,
		sloTerminalStatusFromCleanup(sloLocalCleanupResult{TransitionErr: errors.New("state transition failed")}),
	)
	assert.Equal(
		t,
		slodomain.SLOStatusFailed,
		sloTerminalStatusFromCleanup(sloLocalCleanupResult{SessionRevocationErr: errors.New("session revocation failed")}),
	)
	assert.Equal(
		t,
		slodomain.SLOStatusPartial,
		sloTerminalStatusFromCleanup(sloLocalCleanupResult{ParticipantCleanupErr: errors.New("participant cleanup failed")}),
	)
}

func TestSAMLLogoutResponseReportsCanonicalRevocationFailure(t *testing.T) {
	status := samlLogoutResponseStatusFromCleanup(sloLocalCleanupResult{
		SessionRevocationErr:  errors.New("session revocation failed"),
		ParticipantCleanupErr: errors.New("participant cleanup failed"),
	})

	assert.Equal(t, saml.StatusResponder, status.StatusCode.Value)
	assert.Nil(t, status.StatusCode.StatusCode)

	if assert.NotNil(t, status.StatusMessage) {
		assert.Equal(t, "local browser session revocation failed", status.StatusMessage.Value)
	}
}

func sloDurationSampleCount(t *testing.T, binding, messageType, outcome string) uint64 {
	t.Helper()

	observer, err := sloDurationSeconds.GetMetricWithLabelValues(binding, messageType, outcome)
	if err != nil {
		t.Fatalf("cannot get slo duration observer: %v", err)
	}

	metricObserver, ok := observer.(prometheus.Metric)
	if !ok {
		t.Fatal("slo duration observer does not implement prometheus.Metric")
	}

	metric := &dto.Metric{}
	if err = metricObserver.Write(metric); err != nil {
		t.Fatalf("cannot read slo duration metric: %v", err)
	}

	if metric.Histogram == nil {
		t.Fatal("slo duration metric has no histogram")
	}

	return metric.GetHistogram().GetSampleCount()
}
