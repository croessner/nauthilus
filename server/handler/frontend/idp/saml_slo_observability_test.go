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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/middleware/limit"
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
		slodomain.SLOStatusPartial,
		sloTerminalStatusFromCleanup(sloLocalCleanupResult{ParticipantCleanupErr: errors.New("participant cleanup failed")}),
	)
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
