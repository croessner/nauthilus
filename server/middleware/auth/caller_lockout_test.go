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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
)

// testLockoutPolicy is a small policy whose timing the tests control through explicit clocks.
func testLockoutPolicy() lockoutPolicy {
	return lockoutPolicy{window: time.Minute, blockTime: 2 * time.Minute, sleepOnFail: time.Millisecond, threshold: 3}
}

// TestLockoutPolicyForUsesConfiguredValues pins that configured limits replace the historical defaults.
func TestLockoutPolicyForUsesConfiguredValues(t *testing.T) {
	defaults := lockoutPolicyFor(nil)
	if defaults != (lockoutPolicy{window: time.Minute, blockTime: 2 * time.Minute, sleepOnFail: 300 * time.Millisecond, threshold: 5, exemptThreshold: 50}) {
		t.Fatalf("default policy = %+v", defaults)
	}

	cfg := &config.FileSettings{Server: &config.ServerSection{BackchannelLockout: config.BackchannelLockout{
		Threshold: 7, ExemptThreshold: 70, Window: 30 * time.Second, BlockTime: time.Hour, SleepOnFail: 10 * time.Millisecond,
	}}}

	configured := lockoutPolicyFor(cfg)
	if configured != (lockoutPolicy{window: 30 * time.Second, blockTime: time.Hour, sleepOnFail: 10 * time.Millisecond, threshold: 7, exemptThreshold: 70}) {
		t.Fatalf("configured policy = %+v", configured)
	}
}

// TestFailureLockoutBlocksAfterThresholdAndExpires pins the block lifecycle: the threshold starts one
// block, the block expires after block_time, and counting restarts from zero.
func TestFailureLockoutBlocksAfterThresholdAndExpires(t *testing.T) {
	lockout := newFailureLockout()
	policy := testLockoutPolicy()
	now := time.Now()

	for attempt := range policy.threshold - 1 {
		if lockout.recordFailure("192.0.2.10", policy, now) {
			t.Fatalf("attempt %d started a block below the threshold", attempt+1)
		}
	}

	if !lockout.recordFailure("192.0.2.10", policy, now) {
		t.Fatal("reaching the threshold must start a block")
	}

	if blocked, remaining := lockout.blocked("192.0.2.10", policy, now); !blocked || remaining != policy.blockTime {
		t.Fatalf("blocked() = (%t, %s), want (true, %s)", blocked, remaining, policy.blockTime)
	}

	afterBlock := now.Add(policy.blockTime + time.Second)
	if blocked, _ := lockout.blocked("192.0.2.10", policy, afterBlock); blocked {
		t.Fatal("block must expire after block_time")
	}

	if lockout.recordFailure("192.0.2.10", policy, afterBlock) {
		t.Fatal("counting must restart after a block")
	}
}

// TestFailureLockoutForgetsRejectionsOutsideWindow pins that only rejections within one window count.
func TestFailureLockoutForgetsRejectionsOutsideWindow(t *testing.T) {
	lockout := newFailureLockout()
	policy := testLockoutPolicy()
	now := time.Now()

	for range policy.threshold - 1 {
		lockout.recordFailure("192.0.2.11", policy, now)
	}

	if lockout.recordFailure("192.0.2.11", policy, now.Add(policy.window+time.Second)) {
		t.Fatal("rejections from an elapsed window must not complete the threshold")
	}
}

// TestFailureLockoutStartsExactlyOneBlockUnderConcurrency pins the log-once guarantee under the race detector.
func TestFailureLockoutStartsExactlyOneBlockUnderConcurrency(t *testing.T) {
	lockout := newFailureLockout()
	policy := testLockoutPolicy()
	now := time.Now()

	var (
		waitGroup sync.WaitGroup
		started   atomic.Int32
	)

	for range 64 {
		waitGroup.Go(func() {
			if lockout.recordFailure("192.0.2.12", policy, now) {
				started.Add(1)
			}

			lockout.blocked("192.0.2.12", policy, now)
		})
	}

	waitGroup.Wait()

	if started.Load() < 1 {
		t.Fatal("concurrent rejections must start a block")
	}

	// Rejections after the block started restart counting, so further blocks can only start once the
	// first one has expired. With a single clock instant every later start is impossible.
	if started.Load() != 1 {
		t.Fatalf("blocks started = %d, want exactly 1", started.Load())
	}
}

// httpGuardContext builds a request context with a direct peer and optional forwarding headers.
func httpGuardContext(remoteAddr string, headers map[string]string) *gin.Context {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/api/v1/test", nil)
	ctx.Request.RemoteAddr = remoteAddr

	for name, value := range headers {
		ctx.Request.Header.Set(name, value)
	}

	return ctx
}

// TestNewHTTPCallerGuardClassifiesOnlyTheDirectPeer pins that forwarding headers never claim an exempt
// address, even when a trusted proxy resolves the lockout key from them, and that HTTP client certificates
// never exempt a caller because HTTP has no dedicated backchannel client CA.
func TestNewHTTPCallerGuardClassifiesOnlyTheDirectPeer(t *testing.T) {
	spoofed := map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}
	cfg := &config.FileSettings{Server: &config.ServerSection{TrustedProxies: []string{"10.0.0.5"}}}
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "doppelgaenger"}}

	tests := []struct {
		ctx    *gin.Context
		name   string
		exempt bool
	}{
		{name: "direct loopback peer", ctx: httpGuardContext("127.0.0.1:40000", nil), exempt: true},
		{name: "spoofed headers from untrusted peer", ctx: httpGuardContext("203.0.113.5:40000", spoofed)},
		{name: "loopback forwarded by trusted proxy", ctx: httpGuardContext("10.0.0.5:40000", spoofed)},
		{
			name: "verified client certificate",
			ctx: func() *gin.Context {
				ctx := httpGuardContext("203.0.113.6:40000", nil)
				ctx.Request.TLS = &tls.ConnectionState{
					HandshakeComplete: true,
					PeerCertificates:  []*x509.Certificate{certificate},
					VerifiedChains:    [][]*x509.Certificate{{certificate}},
				}

				return ctx
			}(),
		},
	}

	cfg.Server.BackchannelLockout.TrustedMTLSIdentities = []string{"doppelgaenger"}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NewHTTPCallerGuard(test.ctx, cfg, nil).Exempt(); got != test.exempt {
				t.Fatalf("Exempt() = %t, want %t", got, test.exempt)
			}
		})
	}
}

// TestPresentedCredentialIdentity pins the counting identity without ever retaining a password or token.
func TestPresentedCredentialIdentity(t *testing.T) {
	tests := map[string]struct {
		want   string
		values []string
	}{
		"basic username": {values: []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("svc:secret"))}, want: "basic:svc"},
		"bearer token":   {values: []string{"Bearer opaque-token"}, want: "bearer"},
		"missing":        {want: "none"},
		"other scheme":   {values: []string{"Digest abc"}, want: "other"},
		"broken basic":   {values: []string{"Basic %%%"}, want: "basic:"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := PresentedCredentialIdentity(test.values); got != test.want {
				t.Fatalf("PresentedCredentialIdentity() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestMatchingNetwork pins exact address and prefix matching, including IPv4-mapped IPv6 peers, and that
// the matched entry is returned in canonical form.
func TestMatchingNetwork(t *testing.T) {
	networks := []string{"127.0.0.1/8", "::1", "10.1.2.3"}

	for ip, want := range map[string]string{
		"127.0.0.6":        "127.0.0.0/8",
		"::ffff:127.0.0.1": "127.0.0.0/8",
		"::1":              "::1",
		"10.1.2.3":         "10.1.2.3",
		"10.1.2.4":         "",
		"not-an-ip":        "",
		"":                 "",
	} {
		if got, _ := matchingNetwork(ip, networks); got != want {
			t.Errorf("matchingNetwork(%q) = %q, want %q", ip, got, want)
		}
	}
}

// TestExemptCallerIsBlockedPerPresentedIdentity pins the residual brake for exempt callers.
func TestExemptCallerIsBlockedPerPresentedIdentity(t *testing.T) {
	var bruteForce config.RuntimeModule
	if err := bruteForce.Set(definitions.ControlBruteForce); err != nil {
		t.Fatalf("set brute-force control: %v", err)
	}

	cfg := &config.FileSettings{Server: &config.ServerSection{
		RuntimeModules: []*config.RuntimeModule{&bruteForce},
		BackchannelLockout: config.BackchannelLockout{
			Threshold: 1, ExemptThreshold: 2, SleepOnFail: time.Millisecond,
		},
	}}
	guard := func(presented string) *CallerGuard {
		return NewCallerGuard(cfg, nil, CallerIdentity{IP: "127.0.0.9", PeerIP: "127.0.0.9", Presented: presented, Transport: CallerTransportGRPC})
	}

	callerLockout.reset()
	guard("basic:guesser").Reject("test")

	if blocked, _ := guard("basic:guesser").RejectionThrottled(); blocked {
		t.Fatal("exempt caller must not be blocked by the address threshold")
	}

	guard("basic:guesser").Reject("test")

	if blocked, _ := guard("basic:guesser").RejectionThrottled(); !blocked {
		t.Fatal("exempt identity must be blocked after exempt_threshold rejections")
	}

	if blocked, _ := guard("basic:guesser").Throttled(); blocked {
		t.Fatal("exempt callers must never be refused before their credentials are checked")
	}

	if blocked, _ := guard("bearer").RejectionThrottled(); blocked {
		t.Fatal("another identity behind the exempt address must stay usable")
	}
}

// guardLockoutConfig enables brute-force control with a small lockout and a trusted loopback proxy.
func guardLockoutConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	var bruteForce config.RuntimeModule
	if err := bruteForce.Set(definitions.ControlBruteForce); err != nil {
		t.Fatalf("set brute-force control: %v", err)
	}

	return &config.FileSettings{Server: &config.ServerSection{
		RuntimeModules: []*config.RuntimeModule{&bruteForce},
		TrustedProxies: []string{"127.0.0.1"},
		BackchannelLockout: config.BackchannelLockout{
			Threshold: 2, ExemptThreshold: 4, SleepOnFail: time.Millisecond,
		},
	}}
}

// TestLoopbackProxyClientsAreLockedOutByClientAddress reproduces the review finding: behind a trusted
// reverse proxy on loopback, the resolved client is not exempt, is locked out with the normal threshold,
// and its lockout does not affect other clients behind the same proxy.
func TestLoopbackProxyClientsAreLockedOutByClientAddress(t *testing.T) {
	callerLockout.reset()

	cfg := guardLockoutConfig(t)
	viaProxy := func(client string) *CallerGuard {
		return NewHTTPCallerGuard(httpGuardContext("127.0.0.1:40000", map[string]string{"X-Forwarded-For": client}), cfg, nil)
	}

	if viaProxy("203.0.113.10").Exempt() {
		t.Fatal("a client resolved by a loopback proxy must not be exempt")
	}

	for range 2 {
		viaProxy("203.0.113.10").Reject("test")
	}

	if blocked, _ := viaProxy("203.0.113.10").Throttled(); !blocked {
		t.Fatal("the guessing client must be locked out after threshold rejections")
	}

	if blocked, _ := viaProxy("198.51.100.20").Throttled(); blocked {
		t.Fatal("another client behind the same proxy must not be locked out")
	}
}

// TestProxyProtocolSourceNeverExempts pins that a PROXY header claiming loopback is ignored for the
// exemption, because the connection's TCP upstream is recorded separately.
func TestProxyProtocolSourceNeverExempts(t *testing.T) {
	ctx := httpGuardContext("127.0.0.1:40000", nil)
	ctx.Request = ctx.Request.WithContext(ContextWithTransportPeer(ctx.Request.Context(), "198.51.100.7"))

	if NewHTTPCallerGuard(ctx, &config.FileSettings{Server: &config.ServerSection{}}, nil).Exempt() {
		t.Fatal("a PROXY-supplied loopback source must not exempt a remote TCP peer")
	}

	local := httpGuardContext("127.0.0.1:40000", nil)
	local.Request = local.Request.WithContext(ContextWithTransportPeer(local.Request.Context(), "127.0.0.1"))

	if !NewHTTPCallerGuard(local, &config.FileSettings{Server: &config.ServerSection{}}, nil).Exempt() {
		t.Fatal("a genuine loopback TCP peer must stay exempt")
	}
}

// TestExemptCounterIsSharedAcrossTheExemptNetwork pins that rotating loopback addresses does not reset the
// residual brake, because exempt callers are counted per matched network.
func TestExemptCounterIsSharedAcrossTheExemptNetwork(t *testing.T) {
	callerLockout.reset()

	cfg := guardLockoutConfig(t)
	guard := func(peer string) *CallerGuard {
		return NewCallerGuard(cfg, nil, CallerIdentity{IP: peer, PeerIP: peer, Presented: "basic:rotating", Transport: CallerTransportGRPC})
	}

	for index := range 4 {
		guard(fmt.Sprintf("127.0.0.%d", index+10)).Reject("test")
	}

	if blocked, _ := guard("127.0.0.99").RejectionThrottled(); !blocked {
		t.Fatal("rotating loopback addresses must share one exempt counter")
	}
}

// TestExemptIdentityRegistryOverflowsIntoSharedCounter pins the per-scope bound: once a scope tracks the
// maximum number of identities, new identities share one overflow counter while known ones keep theirs,
// and expired identities free their room.
func TestExemptIdentityRegistryOverflowsIntoSharedCounter(t *testing.T) {
	registry := newExemptIdentityRegistry()
	now := time.Now()

	for index := range maxExemptIdentitiesPerScope {
		if got := registry.resolve("scope", fmt.Sprintf("identity-%d", index), true, time.Minute, now); got != fmt.Sprintf("identity-%d", index) {
			t.Fatalf("identity %d resolved to %q before the bound", index, got)
		}
	}

	if got := registry.resolve("scope", "fresh", true, time.Minute, now); got != exemptOverflowIdentity {
		t.Fatalf("new identity beyond the bound resolved to %q, want overflow", got)
	}

	if got := registry.resolve("scope", "identity-7", false, time.Minute, now); got != "identity-7" {
		t.Fatalf("known identity resolved to %q, want its own counter", got)
	}

	if got := registry.resolve("other-scope", "fresh", true, time.Minute, now); got != "fresh" {
		t.Fatalf("bound must apply per scope, got %q", got)
	}

	if got := registry.resolve("scope", "fresh", true, time.Minute, now.Add(2*time.Minute)); got != "fresh" {
		t.Fatalf("expired identities must free room, got %q", got)
	}
}

// TestExemptScopeOverflowIsBlockedAsAWhole pins that guesses spread over fresh identities beyond the bound
// land in one counter and are blocked after exempt_threshold, while an established identity keeps passing.
func TestExemptScopeOverflowIsBlockedAsAWhole(t *testing.T) {
	callerLockout.reset()

	cfg := guardLockoutConfig(t)
	guard := func(presented string) *CallerGuard {
		return NewCallerGuard(cfg, nil, CallerIdentity{IP: "127.0.0.1", PeerIP: "127.0.0.1", Presented: presented, Transport: CallerTransportGRPC})
	}

	established := guard("bearer")
	established.lockoutKey(true)

	for index := range maxExemptIdentitiesPerScope - 1 {
		guard(fmt.Sprintf("basic:filler-%d", index)).lockoutKey(true)
	}

	for index := range 4 {
		guard(fmt.Sprintf("basic:spray-%d", index)).Reject("test")
	}

	if blocked, _ := guard("basic:spray-new").RejectionThrottled(); !blocked {
		t.Fatal("identities beyond the bound must share the blocked overflow counter")
	}

	if blocked, _ := guard("bearer").RejectionThrottled(); blocked {
		t.Fatal("an established identity must keep its own counter")
	}
}
