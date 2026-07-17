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

package grpcauthority

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	identityv1 "github.com/croessner/nauthilus/v3/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/v3/server/monitoring/authmetrics"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type isolatedGRPCRequestMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	auth     *prometheus.HistogramVec
}

type grpcRequestMetricsCase struct {
	handlerErr error
	name       string
	fullMethod string
	wantMethod string
	wantCode   string
}

// grpcMetricBoundaryProbe observes whether the post-action gate remains open at the metric boundary.
type grpcMetricBoundaryProbe struct {
	executionDone <-chan struct{}
	observed      chan bool
}

// interceptor reports the post-action gate state after the inner chain returns.
func (p *grpcMetricBoundaryProbe) interceptor(
	ctx context.Context,
	req any,
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	response, err := handler(ctx, req)

	select {
	case <-p.executionDone:
		p.observed <- false
	default:
		p.observed <- true
	}

	return response, err
}

// newIsolatedGRPCRequestMetrics creates unregistered collectors for one test.
func newIsolatedGRPCRequestMetrics() *isolatedGRPCRequestMetrics {
	return &isolatedGRPCRequestMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_grpc_requests_total",
			Help: "Test gRPC request count.",
		}, []string{"method", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_grpc_response_time_seconds",
			Help: "Test gRPC response duration.",
		}, []string{"method"}),
		auth: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_authentication_response_time_seconds",
			Help: "Test authentication response duration.",
		}, []string{"transport", "outcome", "protocol"}),
	}
}

// GetGRPCRequestsTotal returns the isolated request counter.
func (m *isolatedGRPCRequestMetrics) GetGRPCRequestsTotal() *prometheus.CounterVec {
	return m.requests
}

// GetGRPCResponseTimeSeconds returns the isolated response histogram.
func (m *isolatedGRPCRequestMetrics) GetGRPCResponseTimeSeconds() *prometheus.HistogramVec {
	return m.duration
}

// GetAuthenticationResponseTimeSeconds returns the isolated auth response histogram.
func (m *isolatedGRPCRequestMetrics) GetAuthenticationResponseTimeSeconds() *prometheus.HistogramVec {
	return m.auth
}

// TestGRPCRequestMetricsRecordsDomainAuthenticationOutcomes verifies business outcomes at the outer boundary.
func TestGRPCRequestMetricsRecordsDomainAuthenticationOutcomes(t *testing.T) {
	testCases := []struct {
		name        string
		response    any
		err         error
		wantOutcome string
	}{
		{name: "success", response: &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_OK}, wantOutcome: authmetrics.OutcomeOK},
		{name: "denial", response: &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_FAIL}, wantOutcome: authmetrics.OutcomeFail},
		{name: "temporary failure", response: &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_TEMPFAIL}, wantOutcome: authmetrics.OutcomeTempFail},
		{name: "unspecified", response: &authv1.AuthResponse{}, wantOutcome: authmetrics.OutcomeError},
		{name: "transport error", err: status.Error(codes.Internal, "failed"), wantOutcome: authmetrics.OutcomeError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := grpcRequestMetricsTestConfig(true)
			metrics := newIsolatedGRPCRequestMetrics()
			interceptor := newGRPCRequestMetrics(cfg, metrics).UnaryServerInterceptor()
			request := &authv1.AuthRequest{Protocol: "SMTP"}

			_, _ = interceptor(
				context.Background(),
				request,
				&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName},
				func(context.Context, any) (any, error) {
					return testCase.response, testCase.err
				},
			)

			count, _ := grpcRequestHistogramValue(
				t,
				metrics.auth,
				authmetrics.TransportGRPC,
				testCase.wantOutcome,
				definitions.ProtoSMTP,
			)
			if count != 1 {
				t.Fatalf("authentication duration count = %d, want 1", count)
			}
		})
	}
}

// TestGRPCRequestMetricsScopesAuthenticationHistogram verifies method and timer gating.
func TestGRPCRequestMetricsScopesAuthenticationHistogram(t *testing.T) {
	testCases := []struct {
		name       string
		method     string
		enabled    bool
		wantSeries int
	}{
		{name: "authenticate enabled", method: authv1.AuthService_Authenticate_FullMethodName, enabled: true, wantSeries: 1},
		{name: "lookup excluded", method: authv1.AuthService_LookupIdentity_FullMethodName, enabled: true},
		{name: "authenticate disabled", method: authv1.AuthService_Authenticate_FullMethodName},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := grpcRequestMetricsTestConfig(testCase.enabled)
			metrics := newIsolatedGRPCRequestMetrics()
			interceptor := newGRPCRequestMetrics(cfg, metrics).UnaryServerInterceptor()

			_, _ = interceptor(
				context.Background(),
				&authv1.AuthRequest{Protocol: definitions.ProtoIMAP},
				&grpc.UnaryServerInfo{FullMethod: testCase.method},
				func(context.Context, any) (any, error) {
					return &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_OK}, nil
				},
			)

			if got := testutil.CollectAndCount(metrics.auth, "test_authentication_response_time_seconds"); got != testCase.wantSeries {
				t.Fatalf("authentication metric series = %d, want %d", got, testCase.wantSeries)
			}
		})
	}
}

// TestGRPCRequestMetricsInterceptorRecordsBoundedMethodAndCode verifies the public metric labels.
func TestGRPCRequestMetricsInterceptorRecordsBoundedMethodAndCode(t *testing.T) {
	for _, testCase := range grpcRequestMetricsCases() {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{})
			cfg.Server.PrometheusTimer.Enabled = true
			metrics := newIsolatedGRPCRequestMetrics()
			interceptor := newGRPCRequestMetrics(cfg, metrics).UnaryServerInterceptor()

			_, err := interceptor(
				context.Background(),
				nil,
				&grpc.UnaryServerInfo{FullMethod: testCase.fullMethod},
				func(context.Context, any) (any, error) {
					return "response", testCase.handlerErr
				},
			)
			if err != testCase.handlerErr {
				t.Fatalf("handler error = %v, want %v", err, testCase.handlerErr)
			}

			if got := grpcRequestCounterValue(t, metrics.requests, testCase.wantMethod, testCase.wantCode); got != 1 {
				t.Fatalf("request count = %v, want 1", got)
			}

			count, _ := grpcRequestHistogramValue(t, metrics.duration, testCase.wantMethod)
			if count != 1 {
				t.Fatalf("duration count = %d, want 1", count)
			}
		})
	}
}

// grpcRequestMetricsCases returns the bounded method and transport-code contract cases.
func grpcRequestMetricsCases() []grpcRequestMetricsCase {
	testCases := grpcRequestSuccessCases()

	return append(testCases, grpcRequestErrorCases()...)
}

// grpcRequestSuccessCases returns successful and bounded-method metric cases.
func grpcRequestSuccessCases() []grpcRequestMetricsCase {
	return []grpcRequestMetricsCase{
		{
			name:       "authenticate success",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			wantMethod: "grpc.authority_authenticate",
			wantCode:   codes.OK.String(),
		},
		{
			name:       "authenticate rejection",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			handlerErr: status.Error(codes.Unauthenticated, "rejected"),
			wantMethod: "grpc.authority_authenticate",
			wantCode:   codes.Unauthenticated.String(),
		},
		{
			name:       "lookup identity success",
			fullMethod: authv1.AuthService_LookupIdentity_FullMethodName,
			wantMethod: "grpc.authority_lookup_identity",
			wantCode:   codes.OK.String(),
		},
		{
			name:       "list accounts success",
			fullMethod: authv1.AuthService_ListAccounts_FullMethodName,
			wantMethod: "grpc.authority_list_accounts",
			wantCode:   codes.OK.String(),
		},
		{
			name:       "identity backend aggregate",
			fullMethod: identityv1.IdentityBackendService_ResolveUser_FullMethodName,
			wantMethod: "grpc.authority_identity_backend",
			wantCode:   codes.OK.String(),
		},
		{
			name:       "unknown method",
			fullMethod: "/untrusted.Service/AttackerControlledMethod",
			wantMethod: "grpc.authority_unknown",
			wantCode:   codes.OK.String(),
		},
		{
			name:       "missing server info",
			wantMethod: "grpc.authority_unknown",
			wantCode:   codes.OK.String(),
		},
	}
}

// grpcRequestErrorCases returns wire-status mapping metric cases.
func grpcRequestErrorCases() []grpcRequestMetricsCase {
	return []grpcRequestMetricsCase{
		{
			name:       "canceled context error",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			handlerErr: context.Canceled,
			wantMethod: "grpc.authority_authenticate",
			wantCode:   codes.Canceled.String(),
		},
		{
			name:       "deadline context error",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			handlerErr: context.DeadlineExceeded,
			wantMethod: "grpc.authority_authenticate",
			wantCode:   codes.DeadlineExceeded.String(),
		},
		{
			name:       "wrapped canceled context error",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			handlerErr: fmt.Errorf("wrapped: %w", context.Canceled),
			wantMethod: "grpc.authority_authenticate",
			wantCode:   codes.Canceled.String(),
		},
		{
			name:       "wrapped deadline context error",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			handlerErr: fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
			wantMethod: "grpc.authority_authenticate",
			wantCode:   codes.DeadlineExceeded.String(),
		},
		{
			name:       "ordinary Go error",
			fullMethod: authv1.AuthService_Authenticate_FullMethodName,
			handlerErr: errors.New("ordinary failure"),
			wantMethod: "grpc.authority_authenticate",
			wantCode:   codes.Unknown.String(),
		},
	}
}

// TestGRPCRequestMetricFamilies verifies the production metric names and label contract.
func TestGRPCRequestMetricFamilies(t *testing.T) {
	productionMetrics := stats.GetMetrics()
	registry := prometheus.NewPedanticRegistry()

	productionMetrics.GetGRPCRequestsTotal().WithLabelValues("test_method", codes.OK.String())
	productionMetrics.GetGRPCResponseTimeSeconds().WithLabelValues("test_method")

	registry.MustRegister(
		productionMetrics.GetGRPCRequestsTotal(),
		productionMetrics.GetGRPCResponseTimeSeconds(),
	)

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather production gRPC metrics: %v", err)
	}

	assertGRPCMetricFamily(t, metricFamilies, "grpc_requests_total", "code", "method")
	assertGRPCMetricFamily(t, metricFamilies, "grpc_response_time_seconds", "method")
}

// TestGRPCRequestMetricsInterceptorHonorsDisabledTimer verifies HTTP-compatible timer gating.
func TestGRPCRequestMetricsInterceptorHonorsDisabledTimer(t *testing.T) {
	cfg := grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{})
	metrics := newIsolatedGRPCRequestMetrics()
	interceptor := newGRPCRequestMetrics(cfg, metrics).UnaryServerInterceptor()

	_, err := interceptor(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName},
		okUnaryHandler,
	)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	method := "grpc.authority_authenticate"
	if got := grpcRequestCounterValue(t, metrics.requests, method, codes.OK.String()); got != 1 {
		t.Fatalf("request count = %v, want 1", got)
	}

	count, _ := grpcRequestHistogramValue(t, metrics.duration, method)
	if count != 0 {
		t.Fatalf("duration count = %d, want 0 with disabled timer", count)
	}
}

// TestGRPCRequestMetricsInterceptorRecordsRecoveredPanic verifies recovery stays inside the metric boundary.
func TestGRPCRequestMetricsInterceptorRecordsRecoveredPanic(t *testing.T) {
	cfg := grpcRequestMetricsTestConfig(true)
	metrics := newIsolatedGRPCRequestMetrics()
	interceptor := unaryServerInterceptor(
		ServerDeps{Cfg: cfg},
		newGRPCRequestMetrics(cfg, metrics).UnaryServerInterceptor(),
	)

	_, err := interceptor(
		grpcRequestMetricsAuthorizedContext(),
		nil,
		&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName},
		func(context.Context, any) (any, error) {
			panic("test panic")
		},
	)
	if status.Code(err) != codes.Internal {
		t.Fatalf("status code = %s, want %s", status.Code(err), codes.Internal)
	}

	method := "grpc.authority_authenticate"
	if got := grpcRequestCounterValue(t, metrics.requests, method, codes.Internal.String()); got != 1 {
		t.Fatalf("request count = %v, want 1", got)
	}

	count, _ := grpcRequestHistogramValue(t, metrics.duration, method)
	if count != 1 {
		t.Fatalf("duration count = %d, want 1", count)
	}
}

// TestGRPCRequestMetricsInterceptorDoesNotWaitForDetachedWork verifies the response gate boundary.
func TestGRPCRequestMetricsInterceptorDoesNotWaitForDetachedWork(t *testing.T) {
	cfg := grpcRequestMetricsTestConfig(true)
	detachedStarted := make(chan struct{})
	releaseDetached := make(chan struct{})
	callDone := make(chan error, 1)
	probe := &grpcMetricBoundaryProbe{
		observed: make(chan bool, 1),
	}
	interceptor := unaryServerInterceptor(ServerDeps{Cfg: cfg}, probe.interceptor)

	go func() {
		_, err := interceptor(
			grpcRequestMetricsAuthorizedContext(),
			nil,
			&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName},
			func(ctx context.Context, _ any) (any, error) {
				probe.executionDone = core.PostActionExecutionDoneFromContext(ctx)
				go func() {
					<-probe.executionDone
					close(detachedStarted)
					<-releaseDetached
				}()

				return "response", nil
			},
		)
		callDone <- err
	}()

	select {
	case gateOpen := <-probe.observed:
		if !gateOpen {
			t.Fatal("post-action gate was released before the metrics boundary completed")
		}
	case <-time.After(time.Second):
		t.Fatal("metrics boundary was not reached")
	}

	select {
	case err := <-callDone:
		if err != nil {
			t.Fatalf("interceptor returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RPC waited for detached work")
	}

	select {
	case <-detachedStarted:
	case <-time.After(time.Second):
		t.Fatal("detached work was not released after the response boundary")
	}

	close(releaseDetached)
}

// TestGRPCRequestMetricsInterceptorRecordsBackchannelRejection verifies security failures stay inside the metric boundary.
func TestGRPCRequestMetricsInterceptorRecordsBackchannelRejection(t *testing.T) {
	cfg := grpcRequestMetricsTestConfig(true)
	metrics := newIsolatedGRPCRequestMetrics()
	interceptor := unaryServerInterceptor(
		ServerDeps{Cfg: cfg},
		newGRPCRequestMetrics(cfg, metrics).UnaryServerInterceptor(),
	)
	handlerCalled := false
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(authorizationMetadataKey, basicAuthorization("grpc-client", "wrong-secret")),
	)

	_, err := interceptor(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName},
		func(context.Context, any) (any, error) {
			handlerCalled = true

			return "response", nil
		},
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("status code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	if handlerCalled {
		t.Fatal("handler was called after backchannel rejection")
	}

	method := "grpc.authority_authenticate"
	if got := grpcRequestCounterValue(t, metrics.requests, method, codes.Unauthenticated.String()); got != 1 {
		t.Fatalf("request count = %v, want 1", got)
	}

	count, _ := grpcRequestHistogramValue(t, metrics.duration, method)
	if count != 1 {
		t.Fatalf("duration count = %d, want 1", count)
	}
}

// TestGRPCRequestMetricsInterceptorObservesAfterHandlerCompletion verifies the synchronous handler boundary.
func TestGRPCRequestMetricsInterceptorObservesAfterHandlerCompletion(t *testing.T) {
	cfg := grpcRequestMetricsTestConfig(true)
	metrics := newIsolatedGRPCRequestMetrics()
	interceptor := unaryServerInterceptor(
		ServerDeps{Cfg: cfg},
		newGRPCRequestMetrics(cfg, metrics).UnaryServerInterceptor(),
	)
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	callDone := make(chan error, 1)

	go func() {
		_, err := interceptor(
			grpcRequestMetricsAuthorizedContext(),
			nil,
			&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName},
			func(context.Context, any) (any, error) {
				close(handlerStarted)
				<-releaseHandler

				return "response", nil
			},
		)
		callDone <- err
	}()

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}

	method := "grpc.authority_authenticate"
	if got := grpcRequestCounterValue(t, metrics.requests, method, codes.OK.String()); got != 0 {
		t.Fatalf("request count while handler is running = %v, want 0", got)
	}

	count, _ := grpcRequestHistogramValue(t, metrics.duration, method)
	if count != 0 {
		t.Fatalf("duration count while handler is running = %d, want 0", count)
	}

	close(releaseHandler)

	select {
	case err := <-callDone:
		if err != nil {
			t.Fatalf("interceptor returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RPC did not complete after handler release")
	}

	if got := grpcRequestCounterValue(t, metrics.requests, method, codes.OK.String()); got != 1 {
		t.Fatalf("request count after handler return = %v, want 1", got)
	}

	count, _ = grpcRequestHistogramValue(t, metrics.duration, method)
	if count != 1 {
		t.Fatalf("duration count after handler return = %d, want 1", count)
	}
}

// grpcRequestMetricsTestConfig creates a timer-enabled or timer-disabled authenticated gRPC test configuration.
func grpcRequestMetricsTestConfig(enabled bool) *config.FileSettings {
	cfg := grpcAuthTestConfig(validBasicAuthConfig(), config.OIDCAuth{})
	cfg.Server.PrometheusTimer.Enabled = enabled

	return cfg
}

// grpcRequestMetricsAuthorizedContext creates valid incoming Basic authentication metadata.
func grpcRequestMetricsAuthorizedContext() context.Context {
	return metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs(authorizationMetadataKey, basicAuthorization("grpc-client", "grpc-secret-1234")),
	)
}

// grpcRequestCounterValue reads one labeled counter value.
func grpcRequestCounterValue(t *testing.T, counter *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()

	metric := &dto.Metric{}
	if err := counter.WithLabelValues(labels...).Write(metric); err != nil {
		t.Fatalf("write counter metric: %v", err)
	}

	return metric.GetCounter().GetValue()
}

// grpcRequestHistogramValue reads one labeled histogram count and sum.
func grpcRequestHistogramValue(t *testing.T, histogram *prometheus.HistogramVec, labels ...string) (uint64, float64) {
	t.Helper()

	metric := &dto.Metric{}
	if err := histogram.WithLabelValues(labels...).(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("write histogram metric: %v", err)
	}

	return metric.GetHistogram().GetSampleCount(), metric.GetHistogram().GetSampleSum()
}

// assertGRPCMetricFamily checks one gathered metric family and its variable labels.
func assertGRPCMetricFamily(t *testing.T, families []*dto.MetricFamily, name string, wantLabels ...string) {
	t.Helper()

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		for _, metric := range family.GetMetric() {
			if grpcMetricLabelValue(metric, "method") != "test_method" {
				continue
			}

			labels := metric.GetLabel()
			if len(labels) != len(wantLabels) {
				t.Fatalf("metric family %q has %d labels, want %d", name, len(labels), len(wantLabels))
			}

			for index, wantLabel := range wantLabels {
				if labels[index].GetName() != wantLabel {
					t.Fatalf("metric family %q label %d = %q, want %q", name, index, labels[index].GetName(), wantLabel)
				}
			}

			return
		}

		t.Fatalf("metric family %q has no test_method series", name)
	}

	t.Fatalf("metric family %q was not gathered", name)
}

// grpcMetricLabelValue returns a gathered metric label value by name.
func grpcMetricLabelValue(metric *dto.Metric, name string) string {
	for _, label := range metric.GetLabel() {
		if label.GetName() == name {
			return label.GetValue()
		}
	}

	return ""
}
