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
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type grpcRequestMetricCollectors interface {
	GetGRPCRequestsTotal() *prometheus.CounterVec
	GetGRPCResponseTimeSeconds() *prometheus.HistogramVec
}

type grpcRequestMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	enabled  bool
}

// newGRPCRequestMetrics creates an observer for the outer gRPC response boundary.
func newGRPCRequestMetrics(cfg config.File, metrics grpcRequestMetricCollectors) *grpcRequestMetrics {
	enabled := false
	if cfg != nil {
		enabled = cfg.GetServer().GetPrometheusTimer().IsEnabled()
	}

	return &grpcRequestMetrics{
		requests: metrics.GetGRPCRequestsTotal(),
		duration: metrics.GetGRPCResponseTimeSeconds(),
		enabled:  enabled,
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

			if m.enabled {
				m.duration.WithLabelValues(method).Observe(time.Since(started).Seconds())
			}
		}()

		return handler(ctx, req)
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
