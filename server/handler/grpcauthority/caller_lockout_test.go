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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	servererrors "github.com/croessner/nauthilus/v4/server/errors"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	lockoutTestThreshold       = 3
	lockoutTestExemptThreshold = 6
)

// tokenStateValidator validates the "valid" token and answers every other token with a fixed error.
type tokenStateValidator struct {
	err error
}

// ValidateToken implements oidcbearer.TokenValidator.
func (v tokenStateValidator) ValidateToken(_ context.Context, token string) (jwt.MapClaims, error) {
	if token == "valid" {
		return grpcBackchannelAccessClaims(definitions.ScopeAuthenticate), nil
	}

	return nil, v.err
}

// lockoutTestConfig enables Bearer auth, brute-force control, and a fast, small lockout. Exempt networks
// keep their loopback default unless given.
func lockoutTestConfig(t *testing.T, exemptNetworks ...string) *config.FileSettings {
	t.Helper()

	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{Enabled: true})
	enableBruteForceControl(t, cfg)

	cfg.Server.BackchannelLockout = config.BackchannelLockout{
		ExemptNetworks:  exemptNetworks,
		Threshold:       lockoutTestThreshold,
		ExemptThreshold: lockoutTestExemptThreshold,
		Window:          time.Minute,
		BlockTime:       time.Minute,
		SleepOnFail:     time.Millisecond,
	}

	return cfg
}

// lockoutTestInterceptor builds the full unary interceptor chain with the given token validator.
func lockoutTestInterceptor(cfg *config.FileSettings, validator oidcbearer.TokenValidator) grpc.UnaryServerInterceptor {
	return UnaryServerInterceptor(ServerDeps{Cfg: cfg, OIDCValidator: validator, Logger: slog.Default()})
}

// callerContext presents authorization from a plain TCP peer.
func callerContext(ctx context.Context, ip string, authorization string) context.Context {
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(authorizationMetadataKey, authorization))

	return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}})
}

// mtlsCallerContext presents authorization over TLS with a client certificate, optionally chain-verified.
func mtlsCallerContext(ip string, authorization string, verified bool) context.Context {
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "doppelgaenger"}}
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate}}

	if verified {
		state.VerifiedChains = [][]*x509.Certificate{{certificate}}
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadataKey, authorization))

	return peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000},
		AuthInfo: credentials.TLSInfo{
			State:          state,
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		},
	})
}

// invokeAuthenticate runs one Authenticate RPC through the interceptor and returns its status code.
func invokeAuthenticate(ctx context.Context, interceptor grpc.UnaryServerInterceptor) codes.Code {
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName}, okUnaryHandler)

	return status.Code(err)
}

// callerAuthCount reads one outcome of the backchannel caller authentication counter.
func callerAuthCount(outcome string, trusted bool) float64 {
	return testutil.ToFloat64(stats.GetMetrics().GetBackchannelCallerAuthTotal().WithLabelValues("grpc", outcome, fmt.Sprint(trusted)))
}

// undecidedValidationCase is one technical token validation failure and its expected gRPC status.
type undecidedValidationCase struct {
	ctx  func() (context.Context, context.CancelFunc)
	err  error
	name string
	ip   string
	want codes.Code
}

// undecidedValidationCases lists technical failures, each from its own address.
func undecidedValidationCases() []undecidedValidationCase {
	return []undecidedValidationCase{
		{
			name: "token store unreachable",
			ip:   "198.51.100.10",
			err:  servererrors.NewTokenValidationUnavailable(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}),
			ctx:  func() (context.Context, context.CancelFunc) { return context.Background(), func() {} },
			want: codes.Unavailable,
		},
		{
			name: "client canceled request",
			ip:   "198.51.100.11",
			err:  servererrors.NewTokenValidationUnavailable(context.Canceled),
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				return ctx, cancel
			},
			want: codes.Canceled,
		},
		{
			name: "client deadline exceeded",
			ip:   "198.51.100.12",
			err:  servererrors.NewTokenValidationUnavailable(context.DeadlineExceeded),
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: codes.DeadlineExceeded,
		},
	}
}

// TestCallerAuthUndecidedValidationIsNeverCounted reproduces the production lockout: technical token
// validation failures from one address must neither lock that address out nor delay later callers.
func TestCallerAuthUndecidedValidationIsNeverCounted(t *testing.T) {
	tests := undecidedValidationCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interceptor := lockoutTestInterceptor(lockoutTestConfig(t), tokenStateValidator{err: test.err})
			unavailableBefore := callerAuthCount("unavailable", false)

			for range 3 * lockoutTestThreshold {
				ctx, cancel := test.ctx()
				code := invokeAuthenticate(callerContext(ctx, test.ip, "Bearer undecided"), interceptor)

				cancel()

				if code != test.want {
					t.Fatalf("undecided validation code = %s, want %s", code, test.want)
				}
			}

			if got := callerAuthCount("unavailable", false) - unavailableBefore; got != 3*lockoutTestThreshold {
				t.Fatalf("unavailable outcomes = %v, want %d", got, 3*lockoutTestThreshold)
			}

			if code := invokeAuthenticate(callerContext(context.Background(), test.ip, "Bearer valid"), interceptor); code != codes.OK {
				t.Fatalf("valid caller after undecided validations code = %s, want OK", code)
			}
		})
	}
}

// TestCallerAuthUntrustedAddressIsStillLockedOut pins that genuine rejections keep locking out untrusted
// addresses after the configured threshold, including for a subsequently valid token.
func TestCallerAuthUntrustedAddressIsStillLockedOut(t *testing.T) {
	const ip = "198.51.100.20"

	interceptor := lockoutTestInterceptor(lockoutTestConfig(t), tokenStateValidator{err: fmt.Errorf("invalid token")})
	throttledBefore := callerAuthCount("throttled", false)

	for attempt := range lockoutTestThreshold {
		if code := invokeAuthenticate(callerContext(context.Background(), ip, "Bearer forged"), interceptor); code != codes.Unauthenticated {
			t.Fatalf("attempt %d code = %s, want Unauthenticated", attempt+1, code)
		}
	}

	if code := invokeAuthenticate(callerContext(context.Background(), ip, "Bearer valid"), interceptor); code != codes.ResourceExhausted {
		t.Fatalf("locked-out caller code = %s, want ResourceExhausted", code)
	}

	if got := callerAuthCount("throttled", false) - throttledBefore; got != 1 {
		t.Fatalf("throttled outcomes = %v, want 1", got)
	}
}

// TestCallerAuthMissingScopeIsNotCounted pins that a valid token without the required scope stays a
// PermissionDenied answer that never locks out the caller.
func TestCallerAuthMissingScopeIsNotCounted(t *testing.T) {
	const ip = "198.51.100.30"

	interceptor := lockoutTestInterceptor(lockoutTestConfig(t), staticTokenValidator{
		claims: grpcBackchannelAccessClaims(definitions.ScopeAuthenticate),
	})

	for range 3 * lockoutTestThreshold {
		_, err := interceptor(
			callerContext(context.Background(), ip, "Bearer token-1"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_ListAccounts_FullMethodName},
			okUnaryHandler,
		)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("missing scope code = %s, want PermissionDenied", status.Code(err))
		}
	}
}

// exemptionCase describes one caller and whether the address lockout exempts it.
type exemptionCase struct {
	configure func(cfg *config.FileSettings)
	ctx       func() context.Context
	name      string
	exempt    bool
}

// exemptionCases covers every exemption source and the look-alikes that must not qualify.
func exemptionCases() []exemptionCase {
	wrongBasic := basicAuthorization("grpc-client", "wrong-secret")
	withMTLSAllowlist := func(cfg *config.FileSettings) {
		cfg.Runtime.Servers.GRPC.Authority.TLS.ClientCA = "/etc/nauthilus/client-ca.pem"
		cfg.Server.BackchannelLockout.TrustedMTLSIdentities = []string{"doppelgaenger"}
	}

	return []exemptionCase{
		{
			name:      "loopback peer by default",
			configure: func(*config.FileSettings) {},
			ctx:       func() context.Context { return callerContext(context.Background(), "127.0.0.1", wrongBasic) },
			exempt:    true,
		},
		{
			name:      "allow-listed mTLS identity verified by the dedicated client CA",
			configure: withMTLSAllowlist,
			ctx:       func() context.Context { return mtlsCallerContext("198.51.100.40", wrongBasic, true) },
			exempt:    true,
		},
		{
			name: "verified mTLS identity outside the allowlist",
			configure: func(cfg *config.FileSettings) {
				withMTLSAllowlist(cfg)
				cfg.Server.BackchannelLockout.TrustedMTLSIdentities = []string{"someone-else"}
			},
			ctx: func() context.Context { return mtlsCallerContext("198.51.100.41", wrongBasic, true) },
		},
		{
			name: "allow-listed identity without dedicated client CA",
			configure: func(cfg *config.FileSettings) {
				cfg.Server.BackchannelLockout.TrustedMTLSIdentities = []string{"doppelgaenger"}
			},
			ctx: func() context.Context { return mtlsCallerContext("198.51.100.42", wrongBasic, true) },
		},
		{
			name:      "unverified client certificate",
			configure: withMTLSAllowlist,
			ctx:       func() context.Context { return mtlsCallerContext("198.51.100.43", wrongBasic, false) },
		},
		{
			name: "trusted proxy address is not exempt",
			configure: func(cfg *config.FileSettings) {
				cfg.Server.TrustedProxies = []string{"198.51.100.44"}
			},
			ctx: func() context.Context { return callerContext(context.Background(), "198.51.100.44", wrongBasic) },
		},
	}
}

// TestCallerAuthExemptionSources pins which callers skip the address lockout. Exempt callers are still
// refused, and after exempt_threshold rejections of one presented identity they are blocked as well.
func TestCallerAuthExemptionSources(t *testing.T) {
	for _, test := range exemptionCases() {
		t.Run(test.name, func(t *testing.T) {
			cfg := lockoutTestConfig(t)
			test.configure(cfg)
			interceptor := lockoutTestInterceptor(cfg, nil)
			rejectedBefore := callerAuthCount("rejected", test.exempt)

			for range lockoutTestThreshold {
				if code := invokeAuthenticate(test.ctx(), interceptor); code != codes.Unauthenticated {
					t.Fatalf("rejection code = %s, want Unauthenticated", code)
				}
			}

			code := invokeAuthenticate(test.ctx(), interceptor)
			if !test.exempt {
				if code != codes.ResourceExhausted {
					t.Fatalf("non-exempt caller code = %s, want ResourceExhausted", code)
				}

				return
			}

			if code != codes.Unauthenticated {
				t.Fatalf("exempt caller code = %s, want Unauthenticated", code)
			}

			if got := callerAuthCount("rejected", true) - rejectedBefore; got != lockoutTestThreshold+1 {
				t.Fatalf("exempt rejected outcomes = %v, want %d", got, lockoutTestThreshold+1)
			}
		})
	}
}

// TestCallerAuthExemptIdentityIsStillBlocked pins the residual brake: one guesser behind an exempt address
// is blocked per presented identity, while another identity from the same address stays usable.
func TestCallerAuthExemptIdentityIsStillBlocked(t *testing.T) {
	const peer = "127.0.0.2"

	interceptor := lockoutTestInterceptor(lockoutTestConfig(t), staticTokenValidator{
		claims: grpcBackchannelAccessClaims(definitions.ScopeAuthenticate),
	})
	guesser := callerContext(context.Background(), peer, basicAuthorization("exempt-guesser", "wrong-secret"))

	for range lockoutTestExemptThreshold {
		if code := invokeAuthenticate(guesser, interceptor); code != codes.Unauthenticated {
			t.Fatalf("guess code = %s, want Unauthenticated", code)
		}
	}

	if code := invokeAuthenticate(guesser, interceptor); code != codes.ResourceExhausted {
		t.Fatalf("guesser after exempt threshold code = %s, want ResourceExhausted", code)
	}

	sidecar := callerContext(context.Background(), peer, "Bearer token-1")
	if code := invokeAuthenticate(sidecar, interceptor); code != codes.OK {
		t.Fatalf("other identity from the exempt address code = %s, want OK", code)
	}
}

// TestCallerAuthExemptValidCredentialsPassBlockedBucket pins that a blocked exempt Bearer counter only
// throttles further rejections: a sidecar with a valid token keeps being accepted.
func TestCallerAuthExemptValidCredentialsPassBlockedBucket(t *testing.T) {
	const peer = "127.0.0.1"

	interceptor := lockoutTestInterceptor(lockoutTestConfig(t), tokenStateValidator{err: fmt.Errorf("invalid token")})
	invalid := callerContext(context.Background(), peer, "Bearer forged")

	for range lockoutTestExemptThreshold {
		invokeAuthenticate(invalid, interceptor)
	}

	if code := invokeAuthenticate(invalid, interceptor); code != codes.ResourceExhausted {
		t.Fatalf("invalid token after exempt threshold code = %s, want ResourceExhausted", code)
	}

	if code := invokeAuthenticate(callerContext(context.Background(), peer, "Bearer valid"), interceptor); code != codes.OK {
		t.Fatalf("valid sidecar token while the Bearer counter is blocked code = %s, want OK", code)
	}
}

// TestCallerAuthMissingValidatorIsUnavailable pins that a wiring fault is neither a rejection nor counted.
func TestCallerAuthMissingValidatorIsUnavailable(t *testing.T) {
	const ip = "198.51.100.60"

	interceptor := lockoutTestInterceptor(lockoutTestConfig(t), nil)

	for range 3 * lockoutTestThreshold {
		if code := invokeAuthenticate(callerContext(context.Background(), ip, "Bearer token"), interceptor); code != codes.Unavailable {
			t.Fatalf("missing validator code = %s, want Unavailable", code)
		}
	}

	if code := invokeAuthenticate(callerContext(context.Background(), ip, basicAuthorization("grpc-client", "grpc-secret-1234")), interceptor); code != codes.OK {
		t.Fatalf("caller after missing-validator answers code = %s, want OK", code)
	}
}

// TestCallerAuthEndedRequestSkipsValidation pins that an already canceled request is answered without
// touching the token validator or the lockout.
func TestCallerAuthEndedRequestSkipsValidation(t *testing.T) {
	validator := &countingTokenValidator{}
	interceptor := lockoutTestInterceptor(lockoutTestConfig(t), validator)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if code := invokeAuthenticate(callerContext(ctx, "198.51.100.61", "Bearer token"), interceptor); code != codes.Canceled {
		t.Fatalf("canceled request code = %s, want Canceled", code)
	}

	if validator.calls.Load() != 0 {
		t.Fatalf("validator calls = %d, want 0", validator.calls.Load())
	}
}

// TestCallerAuthOnlyUnauthenticatedIsCounted pins that statuses other than Unauthenticated never feed the
// lockout, so an unforeseen failure class cannot lock out a caller.
func TestCallerAuthOnlyUnauthenticatedIsCounted(t *testing.T) {
	const ip = "198.51.100.62"

	cfg := lockoutTestConfig(t)
	newGuard := func() *mdauth.CallerGuard {
		return mdauth.NewCallerGuard(cfg, slog.Default(), mdauth.CallerIdentity{IP: ip, PeerIP: ip, Transport: mdauth.CallerTransportGRPC})
	}

	for _, code := range []codes.Code{codes.Internal, codes.Unknown, codes.ResourceExhausted, codes.Unavailable, codes.PermissionDenied} {
		for range lockoutTestThreshold {
			recordCallerAuthOutcome(newGuard(), status.Error(code, "test"))
		}
	}

	if blocked, _ := newGuard().Throttled(); blocked {
		t.Fatal("non-authentication failures must not lock out the caller")
	}

	for range lockoutTestThreshold {
		recordCallerAuthOutcome(newGuard(), status.Error(codes.Unauthenticated, "invalid bearer token"))
	}

	if blocked, _ := newGuard().Throttled(); !blocked {
		t.Fatal("Unauthenticated rejections must lock out the caller")
	}
}

// countingTokenValidator counts validation attempts and rejects every token.
type countingTokenValidator struct {
	calls atomic.Int32
}

// ValidateToken implements oidcbearer.TokenValidator.
func (v *countingTokenValidator) ValidateToken(context.Context, string) (jwt.MapClaims, error) {
	v.calls.Add(1)

	return nil, fmt.Errorf("invalid token")
}

// TestCallerAuthConcurrentRejectionsLockOutOnce exercises the shared lockout from many goroutines so the race
// detector covers the lock-free counting path.
func TestCallerAuthConcurrentRejectionsLockOutOnce(t *testing.T) {
	const ip = "198.51.100.50"

	interceptor := lockoutTestInterceptor(lockoutTestConfig(t), tokenStateValidator{err: fmt.Errorf("invalid token")})

	var (
		waitGroup sync.WaitGroup
		mu        sync.Mutex
		codesSeen = map[codes.Code]int{}
	)

	for range 20 {
		waitGroup.Go(func() {
			code := invokeAuthenticate(callerContext(context.Background(), ip, "Bearer forged"), interceptor)

			mu.Lock()
			codesSeen[code]++
			mu.Unlock()
		})
	}

	waitGroup.Wait()

	if codesSeen[codes.Unauthenticated]+codesSeen[codes.ResourceExhausted] != 20 {
		t.Fatalf("unexpected codes %v", codesSeen)
	}

	if code := invokeAuthenticate(callerContext(context.Background(), ip, "Bearer valid"), interceptor); code != codes.ResourceExhausted {
		t.Fatalf("caller after concurrent rejections code = %s, want ResourceExhausted", code)
	}
}
