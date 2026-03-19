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
	"context"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	sloRequestOutcomeSuccess     = "success"
	sloRequestOutcomeClientError = "client_error"
	sloRequestOutcomeServerError = "server_error"
	sloRequestOutcomeRateLimited = "rate_limited"
	sloRequestOutcomeUnknown     = "unknown"

	sloValidationStagePayload     = "payload"
	sloValidationStageSignature   = "signature"
	sloValidationStageProtocol    = "protocol"
	sloValidationStageTransaction = "transaction"
	sloValidationStageCorrelation = "correlation"
	sloValidationStageAbuseGuard  = "abuse_guard"

	sloAbuseReasonRateLimit     = "rate_limit"
	sloAbuseReasonPayloadTooBig = "payload_too_large"
)

var (
	sloRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_saml_slo_requests_total",
			Help: "Total number of SAML SLO endpoint requests by binding, message type, and outcome.",
		},
		[]string{"binding", "message_type", "outcome"},
	)

	sloValidationErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_saml_slo_validation_errors_total",
			Help: "Total number of SAML SLO validation errors by binding, message type, and stage.",
		},
		[]string{"binding", "message_type", "stage"},
	)

	sloAbuseRejectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_saml_slo_abuse_rejections_total",
			Help: "Total number of SAML SLO endpoint requests rejected by abuse guards.",
		},
		[]string{"reason", "binding"},
	)

	sloTerminalStatusTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_saml_slo_terminal_status_total",
			Help: "Total number of terminal SAML SLO transaction results by direction and status.",
		},
		[]string{"direction", "status"},
	)

	sloDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "idp_saml_slo_duration_seconds",
			Help:    "SAML SLO endpoint latency in seconds by binding, message type, and outcome.",
			Buckets: prometheus.ExponentialBuckets(0.001, 1.8, 14),
		},
		[]string{"binding", "message_type", "outcome"},
	)
)

func observeSLORequest(binding slodomain.SLOBinding, messageType sloMessageType, outcome string, duration time.Duration) {
	bindingLabel := sloMetricBinding(binding)
	messageTypeLabel := sloMetricMessageType(messageType)
	outcomeLabel := normalizeSLOLabelValue(outcome)

	sloRequestsTotal.WithLabelValues(bindingLabel, messageTypeLabel, outcomeLabel).Inc()
	sloDurationSeconds.WithLabelValues(bindingLabel, messageTypeLabel, outcomeLabel).Observe(duration.Seconds())
}

func recordSLOValidationError(stage string, messageType sloMessageType, binding slodomain.SLOBinding) {
	sloValidationErrorsTotal.WithLabelValues(
		sloMetricBinding(binding),
		sloMetricMessageType(messageType),
		normalizeSLOLabelValue(stage),
	).Inc()
}

func recordSLOAbuseRejection(reason string, binding slodomain.SLOBinding) {
	sloAbuseRejectionsTotal.WithLabelValues(
		normalizeSLOLabelValue(reason),
		sloMetricBinding(binding),
	).Inc()
}

func recordSLOTerminalStatus(direction slodomain.SLODirection, status slodomain.SLOStatus) {
	sloTerminalStatusTotal.WithLabelValues(
		sloMetricDirection(direction),
		sloMetricStatus(status),
	).Inc()
}

func sloRequestOutcomeFromHTTPStatus(httpStatus int) string {
	switch {
	case httpStatus == 429:
		return sloRequestOutcomeRateLimited
	case httpStatus >= 200 && httpStatus < 400:
		return sloRequestOutcomeSuccess
	case httpStatus >= 400 && httpStatus < 500:
		return sloRequestOutcomeClientError
	case httpStatus >= 500:
		return sloRequestOutcomeServerError
	default:
		return sloRequestOutcomeUnknown
	}
}

func sloTerminalStatusFromCleanup(cleanupResult sloLocalCleanupResult) slodomain.SLOStatus {
	switch {
	case cleanupResult.ParticipantCleanupErr != nil:
		return slodomain.SLOStatusPartial
	case cleanupResult.TransitionErr != nil:
		return slodomain.SLOStatusFailed
	default:
		return slodomain.SLOStatusDone
	}
}

func sloMetricBinding(binding slodomain.SLOBinding) string {
	switch binding {
	case slodomain.SLOBindingRedirect:
		return string(slodomain.SLOBindingRedirect)
	case slodomain.SLOBindingPost:
		return string(slodomain.SLOBindingPost)
	default:
		return sloRequestOutcomeUnknown
	}
}

func sloMetricMessageType(messageType sloMessageType) string {
	switch messageType {
	case sloMessageTypeRequest:
		return string(sloMessageTypeRequest)
	case sloMessageTypeResponse:
		return string(sloMessageTypeResponse)
	default:
		return sloRequestOutcomeUnknown
	}
}

func sloMetricDirection(direction slodomain.SLODirection) string {
	switch direction {
	case slodomain.SLODirectionSPInitiated:
		return string(slodomain.SLODirectionSPInitiated)
	case slodomain.SLODirectionIDPInitiated:
		return string(slodomain.SLODirectionIDPInitiated)
	default:
		return sloRequestOutcomeUnknown
	}
}

func sloMetricStatus(status slodomain.SLOStatus) string {
	switch status {
	case slodomain.SLOStatusDone:
		return string(slodomain.SLOStatusDone)
	case slodomain.SLOStatusPartial:
		return string(slodomain.SLOStatusPartial)
	case slodomain.SLOStatusFailed:
		return string(slodomain.SLOStatusFailed)
	default:
		return sloRequestOutcomeUnknown
	}
}

func normalizeSLOLabelValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return sloRequestOutcomeUnknown
	}

	return value
}

func (h *SAMLHandler) auditSLOEvent(
	ctx context.Context,
	event string,
	transactionID string,
	requestID string,
	spEntityID string,
	keyvals ...any,
) {
	if h == nil || h.deps == nil || h.deps.Logger == nil {
		return
	}

	attrs := []any{
		definitions.LogKeyMsg, "SAML SLO audit",
		"component", "saml_slo",
		"event", normalizeSLOLabelValue(event),
		"transaction_id", util.WithNotAvailable(strings.TrimSpace(transactionID)),
		"request_id", util.WithNotAvailable(strings.TrimSpace(requestID)),
		"sp_entity_id", util.WithNotAvailable(strings.TrimSpace(spEntityID)),
	}
	attrs = append(attrs, keyvals...)

	level.Info(h.deps.Logger).WithContext(ctx).Log(attrs...)
}
