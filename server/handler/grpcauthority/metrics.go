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
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	"github.com/croessner/nauthilus/v3/server/monitoring/authmetrics"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type grpcRequestMetricCollectors interface {
	GetGRPCRequestsTotal() *prometheus.CounterVec
	GetGRPCResponseTimeSeconds() *prometheus.HistogramVec
	GetAuthenticationResponseTimeSeconds() *prometheus.HistogramVec
}

type grpcRequestMetrics struct {
	requests     *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	authObserver *authmetrics.Observer
	enabled      bool
}

// newGRPCRequestMetrics creates an observer for the outer gRPC response boundary.
func newGRPCRequestMetrics(cfg config.File, metrics grpcRequestMetricCollectors) *grpcRequestMetrics {
	enabled := false
	if cfg != nil {
		enabled = cfg.GetServer().GetPrometheusTimer().IsEnabled()
	}

	return &grpcRequestMetrics{
		requests:     metrics.GetGRPCRequestsTotal(),
		duration:     metrics.GetGRPCResponseTimeSeconds(),
		authObserver: authmetrics.New(cfg, metrics),
		enabled:      enabled,
	}
}

// UnaryServerInterceptor records completed requests and optional response-boundary durations.
func (m *grpcRequestMetrics) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (response any, err error) {
		started := time.Now()
		method := grpcSpanName(grpcFullMethod(info))

		defer func() {
			m.requests.WithLabelValues(method, grpcResponseCode(err).String()).Inc()
			m.observeAuthentication(started, info, req, response, err)

			if m.enabled {
				m.duration.WithLabelValues(method).Observe(time.Since(started).Seconds())
			}
		}()

		return handler(ctx, req)
	}
}

// observeAuthentication records Authenticate domain outcomes at the outer gRPC boundary.
func (m *grpcRequestMetrics) observeAuthentication(
	startedAt time.Time,
	info *grpc.UnaryServerInfo,
	request any,
	response any,
	err error,
) {
	if grpcFullMethod(info) != authv1.AuthService_Authenticate_FullMethodName {
		return
	}

	protocol := ""
	if authRequest, ok := request.(*authv1.AuthRequest); ok && authRequest != nil {
		protocol = authRequest.GetProtocol()
	}

	m.authObserver.Observe(startedAt, authmetrics.TransportGRPC, grpcAuthenticationOutcome(response, err), protocol)
}

// grpcAuthenticationOutcome maps domain responses and transport errors to bounded outcomes.
func grpcAuthenticationOutcome(response any, err error) string {
	if err != nil {
		return authmetrics.OutcomeError
	}

	authResponse, ok := response.(*authv1.AuthResponse)
	if !ok || authResponse == nil {
		return authmetrics.OutcomeError
	}

	switch authResponse.GetDecision() {
	case authv1.AuthDecision_AUTH_DECISION_OK:
		return authmetrics.OutcomeOK
	case authv1.AuthDecision_AUTH_DECISION_FAIL:
		return authmetrics.OutcomeFail
	case authv1.AuthDecision_AUTH_DECISION_TEMPFAIL:
		return authmetrics.OutcomeTempFail
	default:
		return authmetrics.OutcomeError
	}
}

// grpcResponseCode matches grpc-go's conversion of handler errors to wire status codes.
func grpcResponseCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}

	if grpcStatus, ok := status.FromError(err); ok {
		return grpcStatus.Code()
	}

	return status.FromContextError(err).Code()
}
