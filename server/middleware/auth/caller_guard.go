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
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
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
	callerOutcomeThrottled   = "throttled"

	logKeyCallerTransport = "transport"
	logKeyCallerReason    = "reason"
	logKeyCallerExempt    = "exempt"

	// exemptIdentityKeyPrefix separates per-identity counters of exempt callers from address counters.
	exemptIdentityKeyPrefix = "exempt\x00"
	exemptScopeMTLS         = "mtls:"
	exemptScopeNetwork      = "network:"
)

// callerAuthMetrics is the narrow metrics dependency of caller authentication accounting.
type callerAuthMetrics interface {
	GetBackchannelCallerAuthTotal() *prometheus.CounterVec
}

// CallerIdentity describes the transport-level facts that decide how a backchannel caller is accounted.
type CallerIdentity struct {
	// IP is the source address that untrusted callers are locked out by. HTTP may resolve it from
	// forwarding headers of trusted proxies.
	IP string
	// PeerIP is the direct transport peer: the TCP upstream of the connection, even when a PROXY protocol
	// header supplied a different source. It is the only address considered for the exemption, so neither
	// forwarding headers nor PROXY headers can claim an exempt address.
	PeerIP string
	// Presented is the credential identity the request presents, see PresentedCredentialIdentity.
	Presented string
	// Transport is CallerTransportGRPC or CallerTransportHTTP.
	Transport string
	// MTLSIdentities lists the identities of a client certificate verified against a dedicated client CA.
	MTLSIdentities []string
}

// CallerGuard applies failure lockout and outcome accounting to one backchannel caller.
//
// Callers whose direct peer lies in auth.backchannel.failure_lockout.exempt_networks, or whose verified
// client certificate carries an identity from trusted_mtls_identities, are exempt from the address lockout:
// they typically multiplex many independent requests over one address, so an address lockout would reject
// all of them. Exempt callers are counted per (exempt scope, presented identity) with exempt_threshold
// instead, which still stops a single guesser. A caller whose address a trusted proxy resolved to a different
// client is never exempt. A guard serves one request and is not safe for concurrent use.
type CallerGuard struct {
	cfg         config.File
	logger      *slog.Logger
	metrics     callerAuthMetrics
	lockout     *failureLockout
	caller      CallerIdentity
	scope       string
	exemptKnown bool
}

// NewCallerGuard binds the process-wide lockout to caller. Exemption is classified lazily.
func NewCallerGuard(cfg config.File, logger *slog.Logger, caller CallerIdentity) *CallerGuard {
	if logger == nil {
		logger = log.GetLogger()
	}

	return &CallerGuard{
		cfg:     cfg,
		logger:  logger,
		metrics: stats.GetMetrics(),
		lockout: callerLockout,
		caller:  caller,
	}
}

// Exempt reports whether the caller is exempt from the address lockout.
//
// A caller is exempt only when its lockout address is its direct peer. When a trusted proxy resolved a
// different client address, the caller is that client and is locked out by it with the normal threshold;
// exempting the proxy address would let every client behind it guess with the higher exempt threshold.
func (g *CallerGuard) Exempt() bool {
	return g.exemptScope() != ""
}

// exemptScope classifies the caller once and returns what exempts it: the allow-listed mTLS identity or
// the matched exempt network. An empty scope means the caller is not exempt.
func (g *CallerGuard) exemptScope() string {
	if g.exemptKnown {
		return g.scope
	}

	g.exemptKnown = true

	if g.caller.IP != "" && !sameAddress(g.caller.IP, g.caller.PeerIP) {
		return g.scope
	}

	settings := lockoutSettings(g.cfg)

	if identity, ok := firstAllowedIdentity(settings.GetTrustedMTLSIdentities(), g.caller.MTLSIdentities); ok {
		g.scope = exemptScopeMTLS + identity
	} else if network, ok := matchingNetwork(g.caller.PeerIP, settings.GetExemptNetworks()); ok {
		g.scope = exemptScopeNetwork + network
	}

	return g.scope
}

// Throttled reports, before the credentials are checked, whether the caller is locked out and for how much
// longer. Only non-exempt callers are locked out up front, by address. Exempt callers are never refused
// before their credentials are checked, so valid credentials always pass even while a guesser behind the
// same scope is blocked; their block applies through RejectionThrottled. Lockout is enforced only while
// the brute-force control is enabled.
func (g *CallerGuard) Throttled() (bool, time.Duration) {
	if g.Exempt() {
		return false, 0
	}

	return g.throttled()
}

// RejectionThrottled reports, for credentials that were just rejected, whether the caller's counter is
// already blocked. A throttled rejection is answered as throttled and is neither counted nor delayed again.
func (g *CallerGuard) RejectionThrottled() (bool, time.Duration) {
	return g.throttled()
}

// throttled checks the caller's counter without registering a new exempt identity.
func (g *CallerGuard) throttled() (bool, time.Duration) {
	if !bruteForceControlEnabled(g.cfg) {
		return false, 0
	}

	key, policy := g.lockoutKey(false)
	if key == "" || !g.lockout.tracked(key) {
		return false, 0
	}

	blocked, remaining := g.lockout.blocked(key, policy, time.Now())
	if blocked {
		g.observe(callerOutcomeThrottled)
	}

	return blocked, remaining
}

// lockoutKey returns the counter key and policy that apply to this caller. With register, a rejected exempt
// identity claims its own counter if its scope still has room.
func (g *CallerGuard) lockoutKey(register bool) (string, lockoutPolicy) {
	policy := lockoutPolicyFor(g.cfg)

	scope := g.exemptScope()
	if scope == "" {
		return g.caller.IP, policy
	}

	// The presented identity is hashed so that neither usernames nor unbounded input become lockout keys.
	// Keying by the exempt scope instead of the peer address stops a local process from rotating through
	// the loopback network to reset its counter.
	sum := sha256.Sum256([]byte(g.caller.Presented))
	exemptPolicy := policy.forExempt()
	identity := g.lockout.exemptIdentities.resolve(scope, hex.EncodeToString(sum[:16]), register, exemptPolicy.retention(), time.Now())

	return exemptIdentityKeyPrefix + scope + "\x00" + identity, exemptPolicy
}

// Accept records a successful caller authentication.
func (g *CallerGuard) Accept() {
	g.observe(callerOutcomeAccepted)
}

// Reject records a genuine credential rejection and delays it by the configured sleep to slow down
// credential guessing. reason must be a fixed description and never contain credentials.
func (g *CallerGuard) Reject(reason string) {
	g.observe(callerOutcomeRejected)

	key, policy := g.lockoutKey(true)

	if g.Exempt() {
		// Exempt callers are expected to fail rarely; single rejections stay at debug level so a local
		// guesser cannot flood the log. The start of a block is always reported.
		_ = level.Debug(g.logger).Log(
			definitions.LogKeyMsg, "Exempt backchannel caller authentication rejected",
			logKeyCallerTransport, g.caller.Transport,
			definitions.LogKeyClientIP, g.caller.PeerIP,
			logKeyCallerReason, reason,
		)
	}

	if key != "" && g.lockout.recordFailure(key, policy, time.Now()) {
		g.logLockout(policy)
	}

	time.Sleep(policy.sleepOnFail)
}

// Deny records a refused request that is not a credential failure, such as a valid token without the
// required scope. It is neither counted nor delayed, which keeps the pre-existing behavior.
func (g *CallerGuard) Deny() {
	g.observe(callerOutcomeRejected)
}

// Unavailable records a caller authentication that could not be decided for technical reasons.
// It is never counted, because a degraded token store says nothing about the caller's credentials.
func (g *CallerGuard) Unavailable() {
	g.observe(callerOutcomeUnavailable)
}

// logLockout reports the start of one lockout exactly once. It never logs presented identities.
func (g *CallerGuard) logLockout(policy lockoutPolicy) {
	ip := g.caller.IP
	if g.Exempt() {
		ip = g.caller.PeerIP
	}

	_ = level.Warn(g.logger).Log(
		definitions.LogKeyMsg, "Backchannel caller locked out after repeated authentication failures",
		logKeyCallerTransport, g.caller.Transport,
		definitions.LogKeyClientIP, ip,
		logKeyCallerExempt, g.Exempt(),
		"threshold", policy.threshold,
		"window", policy.window.String(),
		"block_time", policy.blockTime.String(),
	)
}

// observe increments the bounded outcome counter.
func (g *CallerGuard) observe(outcome string) {
	if g.metrics == nil {
		return
	}

	g.metrics.GetBackchannelCallerAuthTotal().WithLabelValues(g.caller.Transport, outcome, strconv.FormatBool(g.Exempt())).Inc()
}

// lockoutSettings returns the configured lockout section, or nil for the defaults.
func lockoutSettings(cfg config.File) *config.BackchannelLockout {
	if cfg == nil {
		return nil
	}

	return cfg.GetServer().GetBackchannelLockout()
}

// matchingNetwork returns the configured address or CIDR network that contains ip.
// It parses without logging, because it runs on the request path.
func matchingNetwork(ip string, networks []string) (string, bool) {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}

	address = address.Unmap()

	for _, entry := range networks {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if prefix.Masked().Contains(address) {
				return prefix.Masked().String(), true
			}

			continue
		}

		if network, err := netip.ParseAddr(entry); err == nil && network.Unmap() == address {
			return network.Unmap().String(), true
		}
	}

	return "", false
}

// sameAddress compares two textual addresses after normalizing IPv4-mapped IPv6 forms.
func sameAddress(left string, right string) bool {
	leftAddress, leftErr := netip.ParseAddr(left)
	rightAddress, rightErr := netip.ParseAddr(right)

	if leftErr != nil || rightErr != nil {
		return left == right
	}

	return leftAddress.Unmap() == rightAddress.Unmap()
}

// firstAllowedIdentity returns the first certificate identity that is allow-listed exactly.
func firstAllowedIdentity(allowed []string, identities []string) (string, bool) {
	for _, identity := range identities {
		if slices.Contains(allowed, identity) {
			return identity, true
		}
	}

	return "", false
}

// bruteForceControlEnabled keeps the lockout tied to the brute-force control switch.
func bruteForceControlEnabled(cfg config.File) bool {
	return cfg == nil || cfg.HasRuntimeModule(definitions.ControlBruteForce)
}

// sleepOnFail returns the configured delay for rejected authentications.
func sleepOnFail(cfg config.File) time.Duration {
	return lockoutPolicyFor(cfg).sleepOnFail
}
