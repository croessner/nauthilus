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

package dnsclient

import (
	"errors"
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Lookup results reported to an Observer.
const (
	ResultSuccess  = "success"
	ResultNotFound = "not_found"
	ResultTimeout  = "timeout"
	ResultError    = "error"
)

const (
	metricLabelResult   = "result"
	metricLabelAttempts = "attempts"
	metricLabelSource   = "source"

	socketSourceReused = "reused"
	socketSourceNew    = "new"
)

// Observer receives the outcome of lookups and pool socket leases.
type Observer interface {
	// LookupDone reports the final result of one lookup and how many attempts it started.
	LookupDone(result string, attempts int)

	// SocketLeased reports whether a query reused a pooled socket or opened a new one.
	SocketLeased(reused bool)
}

var (
	lookupsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_lookups_total",
		Help: "Number of finished DNS lookups by result and number of attempts started.",
	}, []string{metricLabelResult, metricLabelAttempts})

	poolSocketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_pool_sockets_total",
		Help: "Number of pooled DNS queries by socket source (reused or new).",
	}, []string{metricLabelSource})
)

// prometheusObserver publishes lookup and pool events as Prometheus counters.
type prometheusObserver struct{}

// LookupDone counts one finished lookup.
func (prometheusObserver) LookupDone(result string, attempts int) {
	lookupsTotal.WithLabelValues(result, strconv.Itoa(attempts)).Inc()
}

// SocketLeased counts one pooled query by socket source.
func (prometheusObserver) SocketLeased(reused bool) {
	source := socketSourceNew
	if reused {
		source = socketSourceReused
	}

	poolSocketsTotal.WithLabelValues(source).Inc()
}

// discardObserver ignores all events.
type discardObserver struct{}

// LookupDone ignores the lookup result.
func (discardObserver) LookupDone(string, int) {}

// SocketLeased ignores the socket lease.
func (discardObserver) SocketLeased(bool) {}

// classifyResult maps a lookup error to its observer result label.
func classifyResult(err error) string {
	if err == nil {
		return ResultSuccess
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return ResultError
	}

	switch {
	case dnsErr.IsNotFound:
		return ResultNotFound
	case dnsErr.IsTimeout:
		return ResultTimeout
	default:
		return ResultError
	}
}

// isTransient reports whether another attempt can still change the outcome.
func isTransient(err error) bool {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return false
	}

	return !dnsErr.IsNotFound && (dnsErr.IsTimeout || dnsErr.IsTemporary)
}
