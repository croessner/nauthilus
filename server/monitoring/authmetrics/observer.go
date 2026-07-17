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

// Package authmetrics provides bounded authentication response-boundary labels.
package authmetrics

import (
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// TransportHTTP identifies the HTTP authentication boundary.
	TransportHTTP = "http"
	// TransportGRPC identifies the gRPC authentication boundary.
	TransportGRPC = "grpc"
	// TransportOther collapses unsupported transports to a bounded label.
	TransportOther = "other"

	// OutcomeOK identifies successful authentication.
	OutcomeOK = "ok"
	// OutcomeFail identifies a domain authentication denial.
	OutcomeFail = "fail"
	// OutcomeTempFail identifies a temporary domain authentication failure.
	OutcomeTempFail = "tempfail"
	// OutcomeError identifies requests without a valid terminal domain decision.
	OutcomeError = "error"

	// ProtocolUnknown identifies requests whose protocol was unavailable.
	ProtocolUnknown = "unknown"
	// ProtocolOther collapses unsupported protocols to a bounded label.
	ProtocolOther = "other"
)

type metricCollectors interface {
	GetAuthenticationResponseTimeSeconds() *prometheus.HistogramVec
}

// Observer records outcome-aware authentication latency at transport boundaries.
type Observer struct {
	duration *prometheus.HistogramVec
	enabled  bool
}

// New constructs an authentication latency observer controlled by the Prometheus timer setting.
func New(cfg config.File, metrics metricCollectors) *Observer {
	enabled := false
	if cfg != nil {
		enabled = cfg.GetServer().GetPrometheusTimer().IsEnabled()
	}

	return &Observer{
		duration: metrics.GetAuthenticationResponseTimeSeconds(),
		enabled:  enabled,
	}
}

// Observe records one completed authentication request with bounded labels.
func (o *Observer) Observe(startedAt time.Time, transport string, outcome string, protocol string) {
	if o == nil || !o.enabled || o.duration == nil {
		return
	}

	transport, outcome, protocol = normalizeLabels(transport, outcome, protocol)
	o.duration.WithLabelValues(transport, outcome, protocol).Observe(time.Since(startedAt).Seconds())
}

// normalizeLabels constrains caller-controlled values to the public metric contract.
func normalizeLabels(transport string, outcome string, protocol string) (string, string, string) {
	return normalizeTransport(transport), normalizeOutcome(outcome), normalizeProtocol(protocol)
}

// normalizeTransport bounds the transport label.
func normalizeTransport(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case TransportHTTP:
		return TransportHTTP
	case TransportGRPC:
		return TransportGRPC
	default:
		return TransportOther
	}
}

// normalizeOutcome bounds the terminal authentication outcome.
func normalizeOutcome(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case OutcomeOK:
		return OutcomeOK
	case OutcomeFail:
		return OutcomeFail
	case OutcomeTempFail:
		return OutcomeTempFail
	default:
		return OutcomeError
	}
}

// normalizeProtocol bounds the caller-controlled protocol while preserving operationally relevant values.
func normalizeProtocol(value string) string {
	protocol := strings.ToLower(strings.TrimSpace(value))
	if protocol == "" {
		return ProtocolUnknown
	}

	switch protocol {
	case definitions.ProtoSMTP,
		definitions.ProtoIMAP,
		definitions.ProtoPOP3,
		definitions.ProtoHTTP,
		definitions.ProtoOIDC,
		definitions.ProtoSAML,
		definitions.ProtoIDP,
		definitions.ProtoAccountProvider,
		definitions.ProtoDefault,
		"https",
		"lmtp",
		"sieve",
		"managesieve":
		return protocol
	default:
		return ProtocolOther
	}
}
