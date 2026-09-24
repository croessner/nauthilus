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
	"log/slog"
	"net"
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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// repeatedCallerAttempts exceeds every former lockout threshold by a wide margin.
const repeatedCallerAttempts = 20

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

// countingTokenValidator counts validation attempts and rejects every token.
type countingTokenValidator struct {
	calls atomic.Int32
}

// ValidateToken implements oidcbearer.TokenValidator.
func (v *countingTokenValidator) ValidateToken(context.Context, string) (jwt.MapClaims, error) {
	v.calls.Add(1)

	return nil, errors.New("invalid token")
}

// callerAccountingTestConfig enables Basic and Bearer auth together with the brute-force control, which
// must never turn into a lockout of backchannel callers.
func callerAccountingTestConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	cfg := grpcAuthTestConfig(config.BasicAuth{
		Enabled:  true,
		Username: "grpc-client",
		Password: secret.New("grpc-secret-1234"),
	}, config.OIDCAuth{Enabled: true})
	enableBruteForceControl(t, cfg)

	return cfg
}

// shortenCallerRejectionDelay keeps the fixed rejection delay out of the test runtime.
func shortenCallerRejectionDelay(t *testing.T) {
	t.Helper()
	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(time.Millisecond))
}

// callerAccountingInterceptor builds the full unary interceptor chain with the given token validator.
func callerAccountingInterceptor(cfg *config.FileSettings, validator oidcbearer.TokenValidator) grpc.UnaryServerInterceptor {
	return UnaryServerInterceptor(ServerDeps{Cfg: cfg, OIDCValidator: validator, Logger: slog.Default()})
}

// callerContext presents authorization from a plain TCP peer.
func callerContext(ctx context.Context, ip string, authorization string) context.Context {
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(authorizationMetadataKey, authorization))

	return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}})
}

// invokeAuthenticate runs one Authenticate RPC through the interceptor and returns its status code.
func invokeAuthenticate(ctx context.Context, interceptor grpc.UnaryServerInterceptor) codes.Code {
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: authv1.AuthService_Authenticate_FullMethodName}, okUnaryHandler)

	return status.Code(err)
}

// callerAuthCount reads one gRPC outcome of the backchannel caller authentication counter.
func callerAuthCount(outcome string) float64 {
	return testutil.ToFloat64(stats.GetMetrics().GetBackchannelCallerAuthTotal().WithLabelValues(mdauth.CallerTransportGRPC, outcome))
}

// TestCallerAuthRepeatedRejectionsNeverBlock pins that a caller address behind which one client keeps
// presenting wrong credentials is never blocked: every rejection stays Unauthenticated and valid Basic and
// Bearer credentials from the same address always pass.
func TestCallerAuthRepeatedRejectionsNeverBlock(t *testing.T) {
	const ip = "198.51.100.20"

	shortenCallerRejectionDelay(t)

	interceptor := callerAccountingInterceptor(callerAccountingTestConfig(t), tokenStateValidator{err: errors.New("invalid token")})
	rejectedBefore := callerAuthCount("rejected")
	acceptedBefore := callerAuthCount("accepted")

	for attempt := range repeatedCallerAttempts {
		authorization := "Bearer forged"
		if attempt%2 == 1 {
			authorization = basicAuthorization("grpc-client", "wrong-secret")
		}

		if code := invokeAuthenticate(callerContext(context.Background(), ip, authorization), interceptor); code != codes.Unauthenticated {
			t.Fatalf("attempt %d code = %s, want Unauthenticated", attempt+1, code)
		}
	}

	if code := invokeAuthenticate(callerContext(context.Background(), ip, "Bearer valid"), interceptor); code != codes.OK {
		t.Fatalf("valid Bearer caller after rejections code = %s, want OK", code)
	}

	if code := invokeAuthenticate(callerContext(context.Background(), ip, basicAuthorization("grpc-client", "grpc-secret-1234")), interceptor); code != codes.OK {
		t.Fatalf("valid Basic caller after rejections code = %s, want OK", code)
	}

	if got := callerAuthCount("rejected") - rejectedBefore; got != repeatedCallerAttempts {
		t.Fatalf("rejected outcomes = %v, want %d", got, repeatedCallerAttempts)
	}

	if got := callerAuthCount("accepted") - acceptedBefore; got != 2 {
		t.Fatalf("accepted outcomes = %v, want 2", got)
	}
}

// TestCallerAuthRejectionIsDelayed pins the fixed delay of a genuine rejection, the only brake left.
func TestCallerAuthRejectionIsDelayed(t *testing.T) {
	const delay = 50 * time.Millisecond

	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(delay))

	interceptor := callerAccountingInterceptor(callerAccountingTestConfig(t), tokenStateValidator{err: errors.New("invalid token")})

	started := time.Now()

	if code := invokeAuthenticate(callerContext(context.Background(), "198.51.100.21", "Bearer forged"), interceptor); code != codes.Unauthenticated {
		t.Fatalf("rejected caller code = %s, want Unauthenticated", code)
	}

	if elapsed := time.Since(started); elapsed < delay {
		t.Fatalf("rejection answered after %s, want at least %s", elapsed, delay)
	}

	started = time.Now()

	if code := invokeAuthenticate(callerContext(context.Background(), "198.51.100.21", "Bearer valid"), interceptor); code != codes.OK {
		t.Fatalf("valid caller code = %s, want OK", code)
	}

	if elapsed := time.Since(started); elapsed >= delay {
		t.Fatalf("accepted caller answered after %s, want no rejection delay", elapsed)
	}
}

// undecidedValidationCase is one technical token validation failure and its expected gRPC status.
type undecidedValidationCase struct {
	ctx  func() (context.Context, context.CancelFunc)
	err  error
	name string
	want codes.Code
}

// undecidedValidationCases lists technical failures that must never read as rejected credentials.
func undecidedValidationCases() []undecidedValidationCase {
	return []undecidedValidationCase{
		{
			name: "token store unreachable",
			err:  servererrors.NewTokenValidationUnavailable(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}),
			ctx:  func() (context.Context, context.CancelFunc) { return context.Background(), func() {} },
			want: codes.Unavailable,
		},
		{
			name: "client canceled request",
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
			err:  servererrors.NewTokenValidationUnavailable(context.DeadlineExceeded),
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: codes.DeadlineExceeded,
		},
	}
}

// TestCallerAuthUndecidedValidationIsUnavailable pins that technical token validation failures answer
// with their own status, are recorded as unavailable and are never delayed like a rejection.
func TestCallerAuthUndecidedValidationIsUnavailable(t *testing.T) {
	// A long delay makes any accidental rejection path visible as a slow test.
	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(time.Minute))

	for _, test := range undecidedValidationCases() {
		t.Run(test.name, func(t *testing.T) {
			interceptor := callerAccountingInterceptor(callerAccountingTestConfig(t), tokenStateValidator{err: test.err})
			unavailableBefore := callerAuthCount("unavailable")
			rejectedBefore := callerAuthCount("rejected")

			for range repeatedCallerAttempts {
				ctx, cancel := test.ctx()
				code := invokeAuthenticate(callerContext(ctx, "198.51.100.10", "Bearer undecided"), interceptor)

				cancel()

				if code != test.want {
					t.Fatalf("undecided validation code = %s, want %s", code, test.want)
				}
			}

			if got := callerAuthCount("unavailable") - unavailableBefore; got != repeatedCallerAttempts {
				t.Fatalf("unavailable outcomes = %v, want %d", got, repeatedCallerAttempts)
			}

			if got := callerAuthCount("rejected") - rejectedBefore; got != 0 {
				t.Fatalf("rejected outcomes = %v, want 0", got)
			}

			if code := invokeAuthenticate(callerContext(context.Background(), "198.51.100.10", "Bearer valid"), interceptor); code != codes.OK {
				t.Fatalf("valid caller after undecided validations code = %s, want OK", code)
			}
		})
	}
}

// TestCallerAuthMissingScopeIsDenied pins that a valid token without the required scope stays a
// PermissionDenied answer, recorded as rejected but never delayed.
func TestCallerAuthMissingScopeIsDenied(t *testing.T) {
	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(time.Minute))

	interceptor := callerAccountingInterceptor(callerAccountingTestConfig(t), staticTokenValidator{
		claims: grpcBackchannelAccessClaims(definitions.ScopeAuthenticate),
	})

	for range repeatedCallerAttempts {
		_, err := interceptor(
			callerContext(context.Background(), "198.51.100.30", "Bearer token-1"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: authv1.AuthService_ListAccounts_FullMethodName},
			okUnaryHandler,
		)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("missing scope code = %s, want PermissionDenied", status.Code(err))
		}
	}
}

// TestCallerAuthMissingValidatorIsUnavailable pins that a wiring fault is answered as unavailable and never
// affects valid Basic credentials.
func TestCallerAuthMissingValidatorIsUnavailable(t *testing.T) {
	const ip = "198.51.100.60"

	t.Cleanup(mdauth.SetCallerRejectionDelayForTest(time.Minute))

	interceptor := callerAccountingInterceptor(callerAccountingTestConfig(t), nil)

	for range repeatedCallerAttempts {
		if code := invokeAuthenticate(callerContext(context.Background(), ip, "Bearer token"), interceptor); code != codes.Unavailable {
			t.Fatalf("missing validator code = %s, want Unavailable", code)
		}
	}

	if code := invokeAuthenticate(callerContext(context.Background(), ip, basicAuthorization("grpc-client", "grpc-secret-1234")), interceptor); code != codes.OK {
		t.Fatalf("caller after missing-validator answers code = %s, want OK", code)
	}
}

// TestCallerAuthEndedRequestSkipsValidation pins that an already canceled request is answered without
// touching the token validator.
func TestCallerAuthEndedRequestSkipsValidation(t *testing.T) {
	validator := &countingTokenValidator{}
	interceptor := callerAccountingInterceptor(callerAccountingTestConfig(t), validator)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if code := invokeAuthenticate(callerContext(ctx, "198.51.100.61", "Bearer token"), interceptor); code != codes.Canceled {
		t.Fatalf("canceled request code = %s, want Canceled", code)
	}

	if validator.calls.Load() != 0 {
		t.Fatalf("validator calls = %d, want 0", validator.calls.Load())
	}
}

// TestRecordCallerAuthOutcomeMapsStatuses pins the accounting of every status class: only Unauthenticated
// is a rejection, PermissionDenied is a denial, and every other status is undecided.
func TestRecordCallerAuthOutcomeMapsStatuses(t *testing.T) {
	shortenCallerRejectionDelay(t)

	tests := []struct {
		err     error
		outcome string
	}{
		{err: nil, outcome: "accepted"},
		{err: status.Error(codes.Unauthenticated, "invalid bearer token"), outcome: "rejected"},
		{err: status.Error(codes.PermissionDenied, "missing scope"), outcome: "rejected"},
		{err: status.Error(codes.Unavailable, "test"), outcome: "unavailable"},
		{err: status.Error(codes.Internal, "test"), outcome: "unavailable"},
		{err: status.Error(codes.ResourceExhausted, "test"), outcome: "unavailable"},
	}

	for _, test := range tests {
		before := callerAuthCount(test.outcome)

		recordCallerAuthOutcome(mdauth.NewCallerAccounting(slog.Default(), mdauth.CallerTransportGRPC, "198.51.100.62"), test.err)

		if got := callerAuthCount(test.outcome) - before; got != 1 {
			t.Fatalf("status %s recorded %v %q outcomes, want 1", status.Code(test.err), got, test.outcome)
		}
	}
}
