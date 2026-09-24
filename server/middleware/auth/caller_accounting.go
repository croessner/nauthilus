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

package auth

import (
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// CallerTransportGRPC labels backchannel callers of the gRPC authority listener.
	CallerTransportGRPC = "grpc"
	// CallerTransportHTTP labels backchannel callers of the HTTP API.
	CallerTransportHTTP = "http"

	callerOutcomeAccepted    = "accepted"
	callerOutcomeRejected    = "rejected"
	callerOutcomeUnavailable = "unavailable"

	logKeyCallerTransport = "transport"
	logKeyCallerReason    = "reason"

	// defaultCallerRejectionDelay slows down credential guessing without ever refusing a caller.
	defaultCallerRejectionDelay = 300 * time.Millisecond
)

// callerRejectionDelay is the fixed delay of every genuine caller rejection. It is deliberately not
// configurable; only tests shorten it through SetCallerRejectionDelayForTest.
var callerRejectionDelay = defaultCallerRejectionDelay

// SetCallerRejectionDelayForTest replaces the rejection delay and returns a function that restores it.
// It exists for tests only and must not be called concurrently with requests.
func SetCallerRejectionDelayForTest(delay time.Duration) func() {
	previous := callerRejectionDelay
	callerRejectionDelay = delay

	return func() {
		callerRejectionDelay = previous
	}
}

// callerAuthMetrics is the narrow metrics dependency of caller authentication accounting.
type callerAuthMetrics interface {
	GetBackchannelCallerAuthTotal() *prometheus.CounterVec
}

// CallerAccounting records the authentication outcome of one backchannel caller.
//
// The backchannel is a tunnel: its caller is protected only by its credentials and by the trusted network
// segment it runs in, while the subject inside the payload is protected by auth.controls brute_force.
// Callers are therefore never blocked. Many callers share one address behind load balancers and sidecars,
// so a lockout by address would turn a single misconfigured caller into an outage for all of them.
type CallerAccounting struct {
	logger    *slog.Logger
	metrics   callerAuthMetrics
	transport string
	clientIP  string
}

// NewCallerAccounting binds the outcome accounting to one caller. clientIP is used for logging only.
func NewCallerAccounting(logger *slog.Logger, transport string, clientIP string) *CallerAccounting {
	if logger == nil {
		logger = log.GetLogger()
	}

	return &CallerAccounting{
		logger:    logger,
		metrics:   stats.GetMetrics(),
		transport: transport,
		clientIP:  clientIP,
	}
}

// Accept records a successful caller authentication.
func (a *CallerAccounting) Accept() {
	a.observe(callerOutcomeAccepted)
}

// Reject records a genuine credential rejection, logs it, and delays the answer by a fixed duration to slow
// down credential guessing. reason must be a fixed description and never contain credentials.
func (a *CallerAccounting) Reject(reason string) {
	a.observe(callerOutcomeRejected)

	_ = level.Warn(a.logger).Log(
		definitions.LogKeyMsg, "Backchannel caller authentication rejected",
		logKeyCallerTransport, a.transport,
		definitions.LogKeyClientIP, a.clientIP,
		logKeyCallerReason, reason,
	)

	time.Sleep(callerRejectionDelay)
}

// Deny records a refused request that is not a credential failure, such as a valid token without the
// required scope. It is not delayed, which keeps the pre-existing behavior.
func (a *CallerAccounting) Deny() {
	a.observe(callerOutcomeRejected)
}

// Unavailable records a caller authentication that could not be decided for technical reasons.
// A degraded token store says nothing about the caller's credentials, so it is neither logged nor delayed.
func (a *CallerAccounting) Unavailable() {
	a.observe(callerOutcomeUnavailable)
}

// observe increments the bounded outcome counter.
func (a *CallerAccounting) observe(outcome string) {
	if a.metrics == nil {
		return
	}

	a.metrics.GetBackchannelCallerAuthTotal().WithLabelValues(a.transport, outcome).Inc()
}
