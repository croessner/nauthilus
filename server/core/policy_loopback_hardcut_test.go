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

package core

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/bruteforce/l1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const (
	hardCutLuaEnvironmentCheck = "lua_environment_current_behavior_environment"
	hardCutLoopbackGuard       = "trusted_loopback_source"
	hardCutLoopbackGuardReason = "scheduler_guard:trusted_loopback_source"
)

type hardCutPreAuthAdapterCase struct {
	configure     func(t *testing.T, cfg *config.FileSettings)
	check         policyruntime.CompiledCheck
	control       string
	name          string
	wantResult    definitions.AuthResult
	wantRBLCalls  int
	username      string
	clientIP      string
	remoteAddr    string
	withGuard     bool
	wantCheckSkip bool
}

func TestPreAuthLoopbackRunsConfiguredChecksWithoutSchedulerGuard(t *testing.T) {
	for _, testCase := range hardCutPreAuthAdapterCases(requestContextLoopbackIP, requestContextLoopbackIP+":12345", false) {
		t.Run(testCase.name, func(t *testing.T) {
			runHardCutPreAuthAdapterCase(t, testCase)
		})
	}
}

func TestPreAuthEmptyIPRunsConfiguredChecksWithoutSchedulerGuard(t *testing.T) {
	for _, testCase := range hardCutPreAuthAdapterCases("", "", false) {
		t.Run(testCase.name, func(t *testing.T) {
			runHardCutPreAuthAdapterCase(t, testCase)
		})
	}
}

func TestPreAuthLoopbackSchedulerGuardSkipsConfiguredChecks(t *testing.T) {
	for _, testCase := range hardCutPreAuthAdapterCases(requestContextLoopbackIP, requestContextLoopbackIP+":12345", true) {
		testCase.wantResult = definitions.AuthResultOK
		testCase.wantRBLCalls = 0
		testCase.wantCheckSkip = true

		t.Run(testCase.name, func(t *testing.T) {
			runHardCutPreAuthAdapterCase(t, testCase)
		})
	}
}

func TestPreAuthSchedulerGuardDoesNotSkipNonLoopbackChecks(t *testing.T) {
	for _, testCase := range hardCutPreAuthAdapterCases("203.0.113.10", "203.0.113.10:12345", true) {
		t.Run(testCase.name, func(t *testing.T) {
			runHardCutPreAuthAdapterCase(t, testCase)
		})
	}
}

func TestStandardAuthDoesNotInjectLoopbackSchedulerGuard(t *testing.T) {
	testCase := hardCutPreAuthAdapterCase{
		name:       "standard auth tls loopback without configured guard",
		control:    definitions.ControlTLSEncryption,
		check:      hardCutCheck(definitions.ControlTLSEncryption, policy.CheckTypeTLSEncryption, policyConfigRefTLS),
		clientIP:   requestContextLoopbackIP,
		remoteAddr: requestContextLoopbackIP + ":12345",
		configure: func(_ *testing.T, cfg *config.FileSettings) {
			cfg.ClearTextList = nil
		},
		wantResult: definitions.AuthResultPreAuthTLS,
	}

	runHardCutPreAuthAdapterCase(t, testCase)
}

func TestBruteForceLoopbackRunsConfiguredCheckWithoutSchedulerGuard(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = requestContextLoopbackIP
	auth.Request.Username = "loopback-blocked@example.test"
	auth.Request.Password = secret.New("blocked-secret")
	ctx.Request.RemoteAddr = requestContextLoopbackIP + ":12345"

	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	l1.GetEngine().Clear()

	l1.GetEngine().Set(
		ctx.Request.Context(),
		l1.KeyNetwork("127.0.0.1/32"),
		l1.Decision{Blocked: true, Rule: hardCutBruteForceRuleName},
		time.Minute,
	)

	expectHardCutBruteForceCheckRedis(mock)

	if !auth.CheckBruteForce(ctx) {
		t.Fatal("expected loopback brute-force check to run and block")
	}

	if auth.Runtime.EnvironmentName != definitions.ControlBruteForce {
		t.Fatalf("environment name = %q, want %q", auth.Runtime.EnvironmentName, definitions.ControlBruteForce)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func TestBruteForceEmptyIPDoesNotUseLocalhostBypass(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = ""

	if auth.CheckBruteForce(ctx) {
		t.Fatal("empty IP without a matching rule must not block")
	}

	if slices.Contains(auth.Runtime.AdditionalLogs, definitions.Localhost) {
		t.Fatalf("additional logs = %#v, want no localhost bypass marker", auth.Runtime.AdditionalLogs)
	}
}

func TestBruteForceLoopbackBucketUpdateRunsWithoutRuntimeBypass(t *testing.T) {
	cfg := hardCutBruteForceConfig(t)
	auth, ctx, mock := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = requestContextLoopbackIP
	auth.Request.Username = "loopback-update@example.test"
	auth.Request.Password = secret.New("update-secret")
	auth.Runtime.AccountName = auth.Request.Username
	auth.Runtime.EnvironmentName = definitions.ControlRBL
	ctx.Request.RemoteAddr = requestContextLoopbackIP + ":12345"
	ctx.Set(definitions.CtxEnvironmentRejectedKey, true)
	ctx.Set(definitions.CtxRWPResultKey, true)
	mock.MatchExpectationsInOrder(false)
	rediscli.ClearScriptCache()
	expectHardCutBucketUpdateRedis(mock)

	auth.UpdateBruteForceBucketsCounter(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func hardCutPreAuthAdapterCases(clientIP string, remoteAddr string, withGuard bool) []hardCutPreAuthAdapterCase {
	return []hardCutPreAuthAdapterCase{
		{
			name:       "lua environment",
			control:    definitions.ControlLua,
			check:      hardCutCheck(hardCutLuaEnvironmentCheck, policy.CheckTypeLuaEnvironment, "auth.policy.attribute_sources.lua.environment.current_behavior_environment"),
			clientIP:   clientIP,
			remoteAddr: remoteAddr,
			configure: func(t *testing.T, _ *config.FileSettings) {
				withCurrentBehaviorLuaEnvironment(t, hardCutLuaTriggerScript())
			},
			wantResult: definitions.AuthResultLuaEnvironment,
			withGuard:  withGuard,
		},
		{
			name:       "tls enforcement",
			control:    definitions.ControlTLSEncryption,
			check:      hardCutCheck(definitions.ControlTLSEncryption, policy.CheckTypeTLSEncryption, policyConfigRefTLS),
			clientIP:   clientIP,
			remoteAddr: remoteAddr,
			configure: func(_ *testing.T, cfg *config.FileSettings) {
				cfg.ClearTextList = nil
			},
			wantResult: definitions.AuthResultPreAuthTLS,
			withGuard:  withGuard,
		},
		{
			name:       "relay domains",
			control:    definitions.ControlRelayDomains,
			check:      hardCutCheck(definitions.ControlRelayDomains, policy.CheckTypeRelayDomains, policyConfigRefRelay),
			clientIP:   clientIP,
			remoteAddr: remoteAddr,
			username:   "user@foreign.test",
			configure: func(_ *testing.T, cfg *config.FileSettings) {
				cfg.RelayDomains = &config.RelayDomainsSection{StaticDomains: []string{"example.test"}}
			},
			wantResult: definitions.AuthResultPreAuthRelayDomain,
			withGuard:  withGuard,
		},
		{
			name:       "rbl",
			control:    definitions.ControlRBL,
			check:      hardCutCheck(definitions.ControlRBL, policy.CheckTypeRBL, policyConfigRefRBL),
			clientIP:   clientIP,
			remoteAddr: remoteAddr,
			configure: func(_ *testing.T, cfg *config.FileSettings) {
				cfg.RBLs = &config.RBLSection{Threshold: 5}
			},
			wantResult:   definitions.AuthResultPreAuthRBL,
			wantRBLCalls: 1,
			withGuard:    withGuard,
		},
	}
}

func runHardCutPreAuthAdapterCase(t *testing.T, testCase hardCutPreAuthAdapterCase) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t, testCase.control)
	if testCase.configure != nil {
		testCase.configure(t, cfg)
	}

	check := testCase.check
	if testCase.withGuard {
		check.SkipIf = []string{hardCutLoopbackGuard}
	}

	activatePolicySnapshotForTest(t, hardCutSnapshot(check, testCase.withGuard))

	var rblService *hardCutRBLService
	if testCase.control == definitions.ControlRBL {
		rblService = registerHardCutRBLService(t)
	}

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	auth.Request.ClientIP = testCase.clientIP
	if strings.TrimSpace(testCase.remoteAddr) != "" {
		ctx.Request.RemoteAddr = testCase.remoteAddr
	}

	if testCase.username != "" {
		auth.Request.Username = testCase.username
	}

	got := auth.HandleEnvironment(ctx)
	if got != testCase.wantResult {
		t.Fatalf("pre-auth result = %v, want %v", got, testCase.wantResult)
	}

	if rblService != nil && rblService.calls != testCase.wantRBLCalls {
		t.Fatalf("rbl calls = %d, want %d", rblService.calls, testCase.wantRBLCalls)
	}

	assertHardCutReport(t, ctx, check.Name, testCase.wantCheckSkip)
}

func assertHardCutReport(t *testing.T, ctx *gin.Context, checkName string, wantSkip bool) {
	t.Helper()

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	check, exists := policyCtx.Report().Checks[checkName]
	if !exists {
		t.Fatalf("missing check report for %q", checkName)
	}

	if !wantSkip {
		if check.Status == policy.CheckStatusSkipped {
			t.Fatalf("check %q status = skipped with reason %q, want adapter execution", checkName, check.Reason)
		}

		return
	}

	if check.Status != policy.CheckStatusSkipped {
		t.Fatalf("check %q status = %q, want %q", checkName, check.Status, policy.CheckStatusSkipped)
	}

	if check.Reason != hardCutLoopbackGuardReason {
		t.Fatalf("check %q skip reason = %q, want %q", checkName, check.Reason, hardCutLoopbackGuardReason)
	}
}

func hardCutSnapshot(check policyruntime.CompiledCheck, includeGuard bool) *policyruntime.Snapshot {
	snapshot := &policyruntime.Snapshot{
		Generation:    90,
		Mode:          policyModeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage:  policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{check},
				},
			},
		},
	}

	if includeGuard {
		snapshot.SchedulerGuards = map[string]policyruntime.CompiledSchedulerGuard{
			hardCutLoopbackGuard: {
				Root:               hardCutLoopbackGuardExpr(),
				OnMissingAttribute: "run",
			},
		}
	}

	return snapshot
}

func hardCutLoopbackGuardExpr() policyruntime.CompiledExpr {
	return policyruntime.CompiledExpr{
		Kind: policyruntime.ExprKindAll,
		Children: []policyruntime.CompiledExpr{
			{
				Kind:        policyruntime.ExprKindAttribute,
				AttributeID: policy.AttributeRequestClientIPPresent,
				Operator:    "is",
				Expected:    policyruntime.TypedValue{Value: true},
			},
			{
				Kind:        policyruntime.ExprKindAttribute,
				AttributeID: policy.AttributeRequestClientIPTrusted,
				Operator:    "is",
				Expected:    policyruntime.TypedValue{Value: true},
			},
			{
				Kind:        policyruntime.ExprKindAttribute,
				AttributeID: policy.AttributeRequestClientIP,
				Operator:    "cidr_contains",
				Expected: policyruntime.TypedValue{Value: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("::1/128"),
				}},
			},
		},
	}
}

func hardCutCheck(name string, checkType string, configRef string) policyruntime.CompiledCheck {
	return policyruntime.CompiledCheck{
		Name:       name,
		Type:       checkType,
		ConfigRef:  configRef,
		Stage:      policy.StagePreAuth,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
	}
}

func hardCutLuaTriggerScript() string {
	return `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`
}

func registerHardCutRBLService(t *testing.T) *hardCutRBLService {
	t.Helper()

	service := &hardCutRBLService{score: 5, threshold: 5}
	previous := GetRBLService()

	RegisterRBLService(service)
	t.Cleanup(func() {
		RegisterRBLService(previous)
	})

	return service
}

type hardCutRBLService struct {
	calls     int
	score     int
	threshold int
}

func (s *hardCutRBLService) Score(*gin.Context, *StateView) (int, error) {
	s.calls++

	return s.score, nil
}

func (s *hardCutRBLService) Threshold() int {
	return s.threshold
}

const hardCutBruteForceRuleName = "loopback_block"

func hardCutBruteForceConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	cfg.BruteForce = &config.BruteForceSection{
		AllowedUniqueWrongPWHashes: 1,
		RWPWindow:                  time.Minute,
		Buckets: []config.BruteForceRule{
			{
				Name:           hardCutBruteForceRuleName,
				Period:         time.Hour,
				CIDR:           32,
				IPv4:           true,
				FailedRequests: 5,
			},
		},
	}
	cfg.Server.BruteForceProtocols = []*config.Protocol{config.NewProtocol(definitions.ProtoIMAP)}

	return cfg
}

func expectHardCutBruteForceCheckRedis(mock redismock.ClientMock) {
	mock.Regexp().ExpectHGet(".*", ".*").RedisNil()
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-current-window")
	mock.Regexp().ExpectEvalSha("sha-current-window", []string{".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
		SetVal([]any{"3", int64(1), "4"})
	mock.ExpectScriptLoad(rediscli.LuaScripts["IncrementAndExpire"]).SetVal("sha-current-burst")
	mock.Regexp().ExpectEvalSha("sha-current-burst", []string{".*"}, ".*").SetVal(int64(2))
	mock.Regexp().ExpectSCard(".*").SetVal(0)
}

func expectHardCutBucketUpdateRedis(mock redismock.ClientMock) {
	mock.ExpectScriptLoad(rediscli.LuaScripts["SlidingWindowCounter"]).SetVal("sha-update-window")
	mock.Regexp().ExpectEvalSha("sha-update-window", []string{".*", ".*"}, ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*", ".*").
		SetVal([]any{"1", int64(0), "1"})
}
