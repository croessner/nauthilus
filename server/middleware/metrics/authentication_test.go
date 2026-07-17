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

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/monitoring/authmetrics"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

type isolatedHTTPMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	auth     *prometheus.HistogramVec
}

// newIsolatedHTTPMetrics creates unregistered collectors for one middleware test.
func newIsolatedHTTPMetrics() *isolatedHTTPMetrics {
	return &isolatedHTTPMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_http_requests_total", Help: "Test requests."}, []string{"path"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_http_response_time_seconds", Help: "Test duration."}, []string{"path"}),
		auth: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "test_authentication_response_time_seconds", Help: "Test auth duration."},
			[]string{"transport", "outcome", "protocol"},
		),
	}
}

func (m *isolatedHTTPMetrics) GetHTTPRequestsTotal() *prometheus.CounterVec {
	return m.requests
}

func (m *isolatedHTTPMetrics) GetHTTPResponseTimeSeconds() *prometheus.HistogramVec {
	return m.duration
}

func (m *isolatedHTTPMetrics) GetAuthenticationResponseTimeSeconds() *prometheus.HistogramVec {
	return m.auth
}

// TestPrometheusMiddlewareRecordsOutcomeAwareAuthenticationLatency verifies HTTP boundary labels.
func TestPrometheusMiddlewareRecordsOutcomeAwareAuthenticationLatency(t *testing.T) {
	testCases := []struct {
		name         string
		category     string
		outcome      string
		protocol     string
		wantSeries   int
		wantOutcome  string
		wantProtocol string
	}{
		{name: "success", category: definitions.CatAuth, outcome: authmetrics.OutcomeOK, protocol: "IMAP", wantSeries: 1, wantOutcome: authmetrics.OutcomeOK, wantProtocol: "imap"},
		{name: "failure", category: definitions.CatAuth, outcome: authmetrics.OutcomeFail, protocol: "SMTP", wantSeries: 1, wantOutcome: authmetrics.OutcomeFail, wantProtocol: "smtp"},
		{name: "temporary failure", category: definitions.CatAuth, outcome: authmetrics.OutcomeTempFail, protocol: "LMTP", wantSeries: 1, wantOutcome: authmetrics.OutcomeTempFail, wantProtocol: "lmtp"},
		{name: "technical error", category: definitions.CatAuth, wantSeries: 1, wantOutcome: authmetrics.OutcomeError, wantProtocol: authmetrics.ProtocolUnknown},
		{name: "non auth route", category: "health", wantOutcome: authmetrics.OutcomeError, wantProtocol: authmetrics.ProtocolUnknown},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := &config.FileSettings{Server: &config.ServerSection{}}
			cfg.Server.PrometheusTimer.Enabled = true
			collectors := newIsolatedHTTPMetrics()
			router := gin.New()
			router.Use(prometheusMiddleware(cfg, collectors))
			router.GET("/test", func(ctx *gin.Context) {
				ctx.Set(definitions.CtxCategoryKey, testCase.category)

				if testCase.outcome != "" {
					ctx.Set(definitions.CtxAuthOutcomeKey, testCase.outcome)
				}

				if testCase.protocol != "" {
					ctx.Set(definitions.CtxAuthProtocolKey, testCase.protocol)
				}

				ctx.Status(http.StatusOK)
			})

			request := httptest.NewRequest(http.MethodGet, "/test", nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			series := testutil.CollectAndCount(collectors.auth, "test_authentication_response_time_seconds")
			if series != testCase.wantSeries {
				t.Fatalf("authentication metric series = %d, want %d", series, testCase.wantSeries)
			}

			if testCase.wantSeries == 0 {
				return
			}

			if got := authenticationHistogramCount(t, collectors.auth, authmetrics.TransportHTTP, testCase.wantOutcome, testCase.wantProtocol); got != 1 {
				t.Fatalf("authentication histogram count = %d, want 1", got)
			}
		})
	}
}

// TestPrometheusMiddlewareHonorsDisabledAuthenticationTimer verifies timer gating.
func TestPrometheusMiddlewareHonorsDisabledAuthenticationTimer(t *testing.T) {
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	collectors := newIsolatedHTTPMetrics()
	router := gin.New()
	router.Use(prometheusMiddleware(cfg, collectors))
	router.GET("/test", func(ctx *gin.Context) {
		ctx.Set(definitions.CtxCategoryKey, definitions.CatAuth)
		ctx.Set(definitions.CtxAuthOutcomeKey, authmetrics.OutcomeOK)
		ctx.Set(definitions.CtxAuthProtocolKey, definitions.ProtoIMAP)
		ctx.Status(http.StatusOK)
	})

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))

	if got := testutil.CollectAndCount(collectors.auth, "test_authentication_response_time_seconds"); got != 0 {
		t.Fatalf("authentication metric series = %d, want 0 with disabled timer", got)
	}
}

// authenticationHistogramCount returns the sample count for one labeled histogram.
func authenticationHistogramCount(t *testing.T, histogram *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()

	metric := &dto.Metric{}
	if err := histogram.WithLabelValues(labels...).(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("write authentication histogram: %v", err)
	}

	return metric.GetHistogram().GetSampleCount()
}
