// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/testing/tracetest"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	facadeHTTPMetricRequests           = "host_http_client_requests_total"
	facadeHTTPMetricDuration           = "host_http_client_duration_seconds"
	facadeHTTPMetricInflight           = "host_http_client_inflight"
	facadeHTTPService                  = "blocklist"
	facadeHTTPMethod                   = "POST"
	facadeHTTPSecret                   = "super-secret"
	facadeHTTPURL                      = "https://blocklist.example.test/check?token=" + facadeHTTPSecret
	facadeTraceHeader                  = "Traceparent"
	facadeHTTPAuthorizationHeader      = "Authorization"
	facadeHTTPAuthorizationValue       = "Bearer " + facadeHTTPSecret
	facadeHTTPAcceptedBody             = `{"ok":true}`
	facadeHTTPSecretResponse           = "super-secret-response-body"
	facadeInitScope                    = "init"
	facadeMetricState                  = "state"
	facadeMetricCold                   = "cold"
	facadeConnectionTargetName         = "blocklist"
	facadeConnectionTargetAddress      = "127.0.0.1:8443"
	facadeConnectionTargetConflictAddr = "127.0.0.1:9443"
	facadeSMTPAddress                  = "127.0.0.1:25"
)

func TestHostHTTPFacadeInjectsTraceHeadersAndRecordsBoundedMetrics(t *testing.T) {
	host, metrics, transport, collector := newHTTPTraceTestHost(t)
	tracer := monittrace.New("nauthilus/test/plugin/http")
	ctx, span := tracer.Start(context.Background(), "parent")

	response, err := host.HTTP(facadeHTTPService).Do(ctx, newHTTPTraceTestRequest())
	if err != nil {
		t.Fatalf("HTTP Do() error = %v", err)
	}

	assertHTTPAcceptedResponse(t, response)
	assertHTTPTraceRequest(t, transport.request)
	assertHTTPMetricObservations(t, metrics)

	span.End()
	assertPluginHTTPSpan(t, collector)
}

func TestHostHTTPFacadeRejectsOversizedResponseAndRedactsLogs(t *testing.T) {
	var logs bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(facadeHTTPSecretResponse)),
		}, nil
	})}
	host := NewHost(
		WithLogger(logger),
		WithHTTPClient(client),
		WithMetricsFactory(func(string) pluginapi.Metrics {
			return NewMetricsFacadeWithRegisterer(facadeHTTPService, prometheus.NewRegistry())
		}),
	)

	_, err := host.HTTP(facadeHTTPService).Do(context.Background(), pluginapi.HTTPRequest{
		Method:           http.MethodGet,
		URL:              facadeHTTPURL,
		Service:          facadeHTTPService,
		MaxResponseBytes: 4,
	})
	if !errors.Is(err, pluginapi.ErrHTTPResponseTooLarge) {
		t.Fatalf("HTTP Do() error = %v, want ErrHTTPResponseTooLarge", err)
	}

	line := logs.String()

	if !strings.Contains(line, httpLogMessageFailure) {
		t.Fatalf("HTTP facade log missing failure message: %s", line)
	}

	for _, secret := range []string{facadeHTTPSecret, facadeHTTPURL, facadeHTTPSecretResponse} {
		if strings.Contains(line, secret) {
			t.Fatalf("HTTP facade log leaked %q: %s", secret, line)
		}
	}
}

func TestMetricsFacadeGaugeAddAndCounterZeroSeries(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetricsFacadeWithRegisterer(facadeInitScope, registry)

	gauge, err := metrics.Gauge(pluginapi.MetricDefinition{
		Name:   "http_client_concurrent_requests_total",
		Help:   "Measure concurrent HTTP client requests",
		Labels: []string{httpLabelService},
	})
	if err != nil {
		t.Fatalf("Gauge() error = %v", err)
	}

	gauge.Add(context.Background(), 1, pluginapi.LabelValue{Name: httpLabelService, Value: facadeHTTPService})
	gauge.Add(context.Background(), -1, pluginapi.LabelValue{Name: httpLabelService, Value: facadeHTTPService})

	counter, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   "security_slow_attack_suspicions_total",
		Help:   "Zero-series counter",
		Labels: []string{facadeMetricState},
	})
	if err != nil {
		t.Fatalf("Counter() error = %v", err)
	}

	counter.Add(context.Background(), 0, pluginapi.LabelValue{Name: facadeMetricState, Value: facadeMetricCold})

	assertGatheredMetricValue(t, registry, "nauthilus_plugin_init_http_client_concurrent_requests_total", 0, httpLabelService, facadeHTTPService)
	assertGatheredMetricValue(t, registry, "nauthilus_plugin_init_security_slow_attack_suspicions_total", 0, facadeMetricState, facadeMetricCold)
}

func TestConnectionTargetFacadeRegistersAndHandlesDuplicates(t *testing.T) {
	recorder := &recordingConnectionTargetRegistrar{}
	host := NewHost(WithConnectionTargets(NewConnectionTargetFacade(recordingConnectionTargetRegistrarAdapter{recorder})))
	target := pluginapi.ConnectionTarget{
		Name:        facadeConnectionTargetName,
		Address:     facadeConnectionTargetAddress,
		Direction:   pluginapi.ConnectionTargetDirectionRemote,
		Description: "Blocklist service",
		Labels:      map[string]string{httpLabelService: facadeHTTPService},
	}

	if err := host.ConnectionTargets(facadeInitScope).Register(context.Background(), target); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := host.ConnectionTargets(facadeInitScope).Register(context.Background(), target); err != nil {
		t.Fatalf("duplicate Register() error = %v, want idempotent nil", err)
	}

	if len(recorder.records) != 1 {
		t.Fatalf("registrar calls = %#v, want one deterministic registration", recorder.records)
	}

	conflict := target
	conflict.Address = facadeConnectionTargetConflictAddr

	if err := host.ConnectionTargets(facadeInitScope).Register(context.Background(), conflict); !errors.Is(err, pluginapi.ErrConnectionTargetConflict) {
		t.Fatalf("conflicting Register() error = %v, want ErrConnectionTargetConflict", err)
	}
}

func TestConnectionTargetFacadeRejectsInvalidTargets(t *testing.T) {
	host := NewHost(WithConnectionTargets(NewConnectionTargetFacade(recordingConnectionTargetRegistrarAdapter{})))

	tests := []struct {
		name   string
		target pluginapi.ConnectionTarget
	}{
		{
			name: "bad name",
			target: pluginapi.ConnectionTarget{
				Name:      "Bad",
				Address:   facadeSMTPAddress,
				Direction: pluginapi.ConnectionTargetDirectionRemote,
			},
		},
		{
			name: "bad address",
			target: pluginapi.ConnectionTarget{
				Name:      facadeSMTPProtocol,
				Address:   "http://127.0.0.1:25/secret",
				Direction: pluginapi.ConnectionTargetDirectionRemote,
			},
		},
		{
			name: "bad direction",
			target: pluginapi.ConnectionTarget{
				Name:      facadeSMTPProtocol,
				Address:   facadeSMTPAddress,
				Direction: "sideways",
			},
		},
		{
			name: "bad label",
			target: pluginapi.ConnectionTarget{
				Name:      facadeSMTPProtocol,
				Address:   facadeSMTPAddress,
				Direction: pluginapi.ConnectionTargetDirectionRemote,
				Labels:    map[string]string{"user": "alice@example.test"},
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := host.ConnectionTargets(facadeInitScope).Register(context.Background(), testCase.target)
			if !errors.Is(err, pluginapi.ErrInvalidConnectionTarget) && !errors.Is(err, pluginapi.ErrInvalidName) {
				t.Fatalf("Register() error = %v, want invalid target/name error", err)
			}
		})
	}
}

type recordingHTTPTransport struct {
	response *http.Response
	request  *http.Request
	err      error
}

// RoundTrip records the outbound request before returning its configured response.
func (t *recordingHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.request = request.Clone(request.Context())

	return t.response, t.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls the wrapped function.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// newHTTPTraceTestHost prepares a host with deterministic HTTP, metrics, and tracing facades.
func newHTTPTraceTestHost(t *testing.T) (*Host, *MetricsFacade, *recordingHTTPTransport, *tracetest.Collector) {
	t.Helper()

	collector := tracetest.Setup(t)
	registry := prometheus.NewRegistry()
	metrics := NewMetricsFacadeWithRegisterer(facadeHTTPService, registry)
	transport := &recordingHTTPTransport{
		response: &http.Response{
			StatusCode: http.StatusAccepted,
			Header: http.Header{
				"Content-Type": {"application/json"},
			},
			Body: io.NopCloser(strings.NewReader(facadeHTTPAcceptedBody)),
		},
	}
	host := NewHost(
		WithHTTPClient(&http.Client{Transport: transport}),
		WithMetricsFactory(func(string) pluginapi.Metrics { return metrics }),
		WithTracerFactory(func(scope string) pluginapi.Tracer { return NewTracerFacade(scope) }),
	)

	return host, metrics, transport, collector
}

// newHTTPTraceTestRequest returns the value API request used by trace propagation tests.
func newHTTPTraceTestRequest() pluginapi.HTTPRequest {
	return pluginapi.HTTPRequest{
		Method:           facadeHTTPMethod,
		URL:              facadeHTTPURL,
		Service:          facadeHTTPService,
		Headers:          map[string][]string{facadeHTTPAuthorizationHeader: {facadeHTTPAuthorizationValue}},
		Body:             []byte(`{"ip":"192.0.2.10"}`),
		Timeout:          time.Second,
		MaxResponseBytes: 64,
	}
}

// assertHTTPAcceptedResponse verifies the value response exposed to plugins.
func assertHTTPAcceptedResponse(t *testing.T, response pluginapi.HTTPResponse) {
	t.Helper()

	if response.StatusCode != http.StatusAccepted || string(response.Body) != facadeHTTPAcceptedBody {
		t.Fatalf("HTTP response = %#v, want accepted JSON response", response)
	}
}

// assertHTTPTraceRequest verifies trace propagation and caller-controlled headers.
func assertHTTPTraceRequest(t *testing.T, request *http.Request) {
	t.Helper()

	if request == nil {
		t.Fatal("HTTP transport was not called")
	}

	if got := request.Header.Get(facadeTraceHeader); got == "" {
		t.Fatal("traceparent header was not injected")
	}

	if got := request.Header.Get(facadeHTTPAuthorizationHeader); got != facadeHTTPAuthorizationValue {
		t.Fatalf("Authorization header = %q, want caller-provided outbound header", got)
	}
}

// assertHTTPMetricObservations verifies request, duration, and inflight accounting.
func assertHTTPMetricObservations(t *testing.T, metrics *MetricsFacade) {
	t.Helper()

	if got := metrics.ObservationCount(facadeHTTPMetricRequests); got != 1 {
		t.Fatalf("request metric observations = %d, want 1", got)
	}

	if got := metrics.ObservationCount(facadeHTTPMetricDuration); got != 1 {
		t.Fatalf("duration metric observations = %d, want 1", got)
	}

	if got := metrics.ObservationCount(facadeHTTPMetricInflight); got != 2 {
		t.Fatalf("inflight metric observations = %d, want increment and decrement", got)
	}
}

// assertPluginHTTPSpan verifies that the host HTTP facade exported a child span.
func assertPluginHTTPSpan(t *testing.T, collector *tracetest.Collector) {
	t.Helper()

	if _, ok := tracetest.FindByNameAndAttributes(collector.Spans(), "plugin.http"); !ok {
		t.Fatalf("plugin HTTP span not exported: %#v", collector.Spans())
	}
}

type recordingConnectionTargetRegistrar struct {
	records []connectionTargetRegistration
}

type connectionTargetRegistration struct {
	description string
	direction   string
	address     string
}

type recordingConnectionTargetRegistrarAdapter struct {
	recorder *recordingConnectionTargetRegistrar
}

// Register records one connection target registration.
func (a recordingConnectionTargetRegistrarAdapter) Register(_ context.Context, address string, direction string, description string) {
	if a.recorder == nil {
		return
	}

	a.recorder.records = append(a.recorder.records, connectionTargetRegistration{
		address:     address,
		direction:   direction,
		description: description,
	})
}

// Count returns zero for test targets.
func (a recordingConnectionTargetRegistrarAdapter) Count(string) (int, bool) {
	return 0, false
}

// assertGatheredMetricValue checks one gathered metric sample and label value.
func assertGatheredMetricValue(t *testing.T, registry *prometheus.Registry, familyName string, value float64, labelName string, labelValue string) {
	t.Helper()

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}

		for _, metric := range family.GetMetric() {
			if !prometheusMetricHasLabel(metric, labelName, labelValue) {
				continue
			}

			if metricValue(metric) != value {
				t.Fatalf("%s value = %f, want %f", familyName, metricValue(metric), value)
			}

			return
		}
	}

	t.Fatalf("metric %s with %s=%s was not gathered", familyName, labelName, labelValue)
}

// metricValue extracts the numeric value from one Prometheus metric sample.
func metricValue(metric *dto.Metric) float64 {
	switch {
	case metric.GetGauge() != nil:
		return metric.GetGauge().GetValue()
	case metric.GetCounter() != nil:
		return metric.GetCounter().GetValue()
	default:
		return 0
	}
}
