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
	"net/http"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/bruteforce"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	testRBLNameSpamhaus              = "Zen Spamhaus"
	testProtocolIMAP                 = "imap"
	testProtocolSMTP                 = "smtp"
	testPluginEnvironmentConfigRef   = "plugins.modules.geoip.environment"
	testSchedulerGuardInsecure       = "insecure_connection"
	testSchedulerGuardInsecureReason = "scheduler_guard:insecure_connection"
)

func TestAuthPathCollectsTLSCheckWithoutChangingPreAuthDecision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    73,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       definitions.ControlTLSEncryption,
							Type:       policy.CheckTypeTLSEncryption,
							ConfigRef:  policyConfigRefTLS,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
					},
				},
			},
		},
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultPreAuthTLS {
		t.Fatalf("pre-auth result = %v, want %v", got, definitions.AuthResultPreAuthTLS)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if got := report.Checks[definitions.ControlTLSEncryption].Status; got != policy.CheckStatusOK {
		t.Fatalf("tls check status = %q, want %q", got, policy.CheckStatusOK)
	}

	if got := report.Attributes["auth.tls.secure"].Value; got != false {
		t.Fatalf("tls secure attribute = %v, want false", got)
	}
}

func TestAuthPathSchedulerGuardSkipsTLSAdapter(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, schedulerGuardTLSSnapshot("enforce"))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultOK {
		t.Fatalf("pre-auth result = %v, want %v", got, definitions.AuthResultOK)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()

	check := report.Checks[definitions.ControlTLSEncryption]
	if check.Status != policy.CheckStatusSkipped {
		t.Fatalf("tls check status = %q, want %q", check.Status, policy.CheckStatusSkipped)
	}

	if check.Reason != testSchedulerGuardInsecureReason {
		t.Fatalf("tls skip reason = %q, want %s", check.Reason, testSchedulerGuardInsecureReason)
	}

	if _, exists := report.Attributes[policy.AttributeTLSSecure]; exists {
		t.Fatal("tls adapter emitted attributes although scheduler guard skipped the check")
	}
}

func TestAuthPathObserveSchedulerGuardDoesNotSkipTLSAdapter(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, schedulerGuardTLSSnapshot("observe"))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultPreAuthTLS {
		t.Fatalf("pre-auth result = %v, want %v", got, definitions.AuthResultPreAuthTLS)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()

	check := report.Checks[definitions.ControlTLSEncryption]
	if check.Status != policy.CheckStatusOK {
		t.Fatalf("tls check status = %q, want %q", check.Status, policy.CheckStatusOK)
	}

	if _, exists := report.Attributes[policy.AttributeTLSSecure]; !exists {
		t.Fatal("tls adapter did not emit attributes in observe mode")
	}
}

func TestAuthPathRunsConfiguredPluginEnvironmentBridge(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	bridge := &recordingPluginEnvironmentBridge{triggered: true}
	previous := regPluginEnv

	RegisterPluginEnvironmentSourceBridge(bridge)
	t.Cleanup(func() {
		RegisterPluginEnvironmentSourceBridge(previous)
	})
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    81,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "plugin_environment_geoip",
							Type:       policy.CheckTypePluginEnvironment,
							ConfigRef:  testPluginEnvironmentConfigRef,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
					},
				},
			},
		},
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultLuaEnvironment {
		t.Fatalf("pre-auth result = %v, want %v", got, definitions.AuthResultLuaEnvironment)
	}

	if bridge.calls != 1 {
		t.Fatalf("plugin environment calls = %d, want 1", bridge.calls)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	check := policyCtx.Report().Checks["plugin_environment_geoip"]
	if check.Type != policy.CheckTypePluginEnvironment || !check.Matched {
		t.Fatalf("plugin check = %#v, want matched plugin.environment check", check)
	}
}

func TestAuthBoundaryCustomObserveDoesNotChangeDefaultDecision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, customObserveTLSSnapshot())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServJSON
	auth.SetStatusCodes(auth.Request.Service)

	auth.runAuthPipelineFSM(ctx)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if report.Final == nil || report.Final.PolicyName != "standard_tls_enforcement" {
		t.Fatalf("final = %#v, want authoritative TLS default", report.Final)
	}

	if report.Observe == nil || !report.Observe.Mismatch {
		t.Fatalf("observe report = %#v, want custom mismatch", report.Observe)
	}

	if report.Observe.Shadow == nil || report.Observe.Shadow.PolicyName != "custom_deny_tls" {
		t.Fatalf("custom shadow = %#v, want custom_deny_tls", report.Observe.Shadow)
	}

	if got := ctx.Writer.Status(); got != http.StatusInternalServerError {
		t.Fatalf("HTTP status = %d, want default tempfail status", got)
	}
}

func TestAuthBoundaryConfiguredPreAuthEnforceOverridesCurrentTLSResult(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, customEnforceTLSSnapshot(customEnforceTLSDenyPolicy(false)))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServJSON
	auth.SetStatusCodes(auth.Request.Service)

	auth.runAuthPipelineFSM(ctx)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if report.Final == nil || report.Final.PolicyName != "custom_deny_tls" {
		t.Fatalf("final = %#v, want configured TLS denial", report.Final)
	}

	if got := ctx.Writer.Status(); got != http.StatusForbidden {
		t.Fatalf("HTTP status = %d, want configured denial status", got)
	}

	if got := auth.Runtime.StatusMessage; got != "Custom TLS deny" {
		t.Fatalf("status message = %q, want configured message", got)
	}
}

func TestAuthBoundaryConfiguredPreAuthEnforceLetsUnmatchedTLSContinue(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, customEnforceTLSSnapshot(customEnforceTLSDenyPolicy(true)))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultOK {
		t.Fatalf("pre-auth result = %v, want OK", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Final != nil {
		t.Fatalf("final = %#v, want nil", policyCtx.Report().Final)
	}
}

func TestConfiguredPreAuthControlAtBruteForceSkipsLaterChecks(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, customEnforcePreAuthControlSnapshot())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.recordPolicyBruteForce(ctx, true)

	if auth.applyConfiguredPreAuthDecision(ctx) {
		t.Fatal("neutral pre-auth control must not apply a terminal decision")
	}

	if !auth.applyConfiguredPreAuthControl(ctx, definitions.AuthResultFail) {
		t.Fatal("configured brute-force control was not applied")
	}

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultOK {
		t.Fatalf("pre-auth result = %v, want OK", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if _, exists := policyCtx.Report().Checks[definitions.ControlTLSEncryption]; exists {
		t.Fatal("tls check was collected after pre-auth control skipped remaining checks")
	}

	if got := len(policyCtx.Report().Policies); got != 1 {
		t.Fatalf("selected policies = %d, want one configured control decision", got)
	}
}

func TestRecordPolicyBruteForceEmitsBucketFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	activatePolicySnapshotForTest(t, customEnforcePreAuthControlSnapshot())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Runtime.BFRWP = true
	auth.Runtime.BruteForceBuckets = []bruteforce.BucketPolicyFact{
		{
			Name:           "IMAP Short",
			ClientNet:      "192.0.2.0/24",
			Count:          4,
			Limit:          5,
			EffectiveLimit: 4,
			Remaining:      0,
			Ratio:          1,
			Period:         time.Minute,
			BanTime:        time.Hour,
			CIDR:           24,
			Matched:        true,
			OverLimit:      true,
			Repeating:      true,
		},
	}

	auth.recordPolicyBruteForce(ctx, true)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if got := report.Attributes["auth.brute_force.bucket.imap_short.count"].Value; got != float64(4) {
		t.Fatalf("bucket count = %#v, want 4", got)
	}

	if got := report.Attributes["auth.brute_force.bucket.imap_short.over_limit"].Value; got != true {
		t.Fatalf("bucket over_limit = %#v, want true", got)
	}

	if got := report.Attributes[policy.AttributeBruteForceRWPActive].Value; got != true {
		t.Fatalf("rwp active = %#v, want true", got)
	}

	if got := report.Attributes[policy.AttributeBruteForceBucketTriggeredCount].Value; got != float64(1) {
		t.Fatalf("triggered bucket count = %#v, want 1", got)
	}
}

func TestRecordPolicyBruteForceEmitsTolerationFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	activatePolicySnapshotForTest(t, customEnforcePreAuthControlSnapshot())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Runtime.BruteForceToleration = tolerate.PolicyFact{
		TTL:             15 * time.Minute,
		Mode:            "adaptive",
		Positive:        20,
		Negative:        2,
		MaxNegative:     5,
		Percent:         25,
		Active:          true,
		Custom:          true,
		SuppressedBlock: true,
	}

	auth.recordPolicyBruteForce(ctx, false)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if got := report.Attributes[policy.AttributeBruteForceTolerationActive].Value; got != true {
		t.Fatalf("toleration active = %#v, want true", got)
	}

	if got := report.Attributes[policy.AttributeBruteForceTolerationMode].Value; got != "adaptive" {
		t.Fatalf("toleration mode = %#v, want adaptive", got)
	}

	if got := report.Attributes[policy.AttributeBruteForceTolerationSuppressedBlock].Value; got != true {
		t.Fatalf("suppressed block = %#v, want true", got)
	}

	if got := report.Attributes[policy.AttributeBruteForceTolerationTTLSeconds].Value; got != float64(900) {
		t.Fatalf("ttl seconds = %#v, want 900", got)
	}
}

func TestRecordPolicyRBLEmitsAggregateAndListFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlRBL)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    77,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Runtime.RBLPolicy = RBLPolicyFact{
		Score:                  7,
		Threshold:              5,
		MatchedCount:           1,
		ListCount:              2,
		AllowFailureErrorCount: 1,
		MatchedLists:           []string{testRBLNameSpamhaus},
		Lists: []RBLListPolicyFact{
			{
				Name:         testRBLNameSpamhaus,
				Host:         "zen.spamhaus.org",
				Query:        "10.113.0.203.zen.spamhaus.org",
				ReturnCode:   "127.0.0.2",
				IPFamily:     "ipv4",
				Weight:       7,
				Listed:       true,
				AllowFailure: false,
			},
			{
				Name:         "Timeout List",
				Host:         "timeout.example.test",
				ReasonCode:   "dns_error",
				Weight:       3,
				Error:        true,
				AllowFailure: true,
			},
		},
	}

	auth.recordPolicyRBL(ctx, true, nil)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if got := report.Attributes[policy.AttributeRBLScore].Value; got != float64(7) {
		t.Fatalf("rbl score = %#v, want 7", got)
	}

	if got := report.Attributes[policy.AttributeRBLMatchedLists].Value; len(got.([]string)) != 1 || got.([]string)[0] != testRBLNameSpamhaus {
		t.Fatalf("matched lists = %#v, want Zen Spamhaus", got)
	}

	if got := report.Attributes["auth.rbl.list.zen_spamhaus.listed"].Value; got != true {
		t.Fatalf("zen listed = %#v, want true", got)
	}

	if got := report.Attributes["auth.rbl.list.timeout_list.allow_failure"].Value; got != true {
		t.Fatalf("timeout allow_failure = %#v, want true", got)
	}
}

func TestRecordPolicyRelayDomainsEmitsPolicyFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlRelayDomains)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    78,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Runtime.RelayDomainPolicy = RelayDomainPolicyFact{
		Value:           "external.example",
		ConfiguredCount: 2,
		Present:         true,
		Rejected:        true,
	}

	auth.recordPolicyRelayDomains(ctx, true)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if got := report.Attributes[policy.AttributeRelayDomainValue].Value; got != "external.example" {
		t.Fatalf("relay domain value = %#v, want external.example", got)
	}

	if got := report.Attributes[policy.AttributeRelayDomainRejected].Value; got != true {
		t.Fatalf("relay rejected = %#v, want true", got)
	}

	if got := report.Attributes[policy.AttributeRelayDomainConfiguredCount].Value; got != float64(2) {
		t.Fatalf("configured count = %#v, want 2", got)
	}
}

func TestRecordPolicyBackendResultExportsConfiguredSubjectAttributes(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Auth = &config.AuthSection{
		Policy: config.AuthPolicySection{
			Mode:          "enforce",
			DefaultPolicy: policy.BuiltinDefaultSet,
			AttributeExports: []config.PolicyAttributeExportConfig{
				{Name: "Account Status", Attribute: "accountStatus", Type: "string"},
				{Name: "Risk Score", Attribute: "riskScore", Type: "number"},
				{Name: "Entitlements", Attribute: "entitlements", Type: "string_list"},
			},
		},
	}
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    79,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	passDBResult := &PassDBResult{
		Authenticated: true,
		Backend:       definitions.BackendLDAP,
		Attributes: bktype.AttributeMapping{
			"accountStatus": {"locked"},
			"riskScore":     {"42.5"},
			"entitlements":  {testProtocolIMAP, testProtocolSMTP},
		},
	}

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()

	status := report.Attributes["auth.subject.attribute.account_status"]
	if got := status.Value; got != true {
		t.Fatalf("account status present = %#v, want true", got)
	}

	if got := status.Details["value"].Value; got != "locked" {
		t.Fatalf("account status value = %#v, want locked", got)
	}

	if got := report.Attributes["auth.subject.attribute.risk_score"].Details["value"].Value; got != float64(42.5) {
		t.Fatalf("risk score = %#v, want 42.5", got)
	}

	values := report.Attributes["auth.subject.attribute.entitlements"].Details["values"].Value.([]string)
	if len(values) != 2 || values[0] != testProtocolIMAP || values[1] != testProtocolSMTP {
		t.Fatalf("entitlements = %#v, want imap/smtp", values)
	}
}

func TestRecordPolicyBackendResultEmitsLDAPMasterUserFact(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.MasterUser = config.MasterUser{Enabled: true, UserFormat: config.DefaultMasterUserFormat}

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    80,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Username = testMasterUserFormattedName
	passDBResult := &PassDBResult{
		Authenticated: true,
		Backend:       definitions.BackendLDAP,
	}

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	attributeValue, ok := policyCtx.Report().Attributes[policy.AttributeMasterUserActive]
	if !ok {
		t.Fatal("missing master-user policy attribute")
	}

	if got := attributeValue.Value; got != true {
		t.Fatalf("master-user active = %#v, want true", got)
	}

	if got := attributeValue.Details["master_user"].Value; got != testMasterUserAdminAccount {
		t.Fatalf("master_user detail = %#v, want %s", got, testMasterUserAdminAccount)
	}

	if got := attributeValue.Details["target_user"].Value; got != testMasterUserTargetAccount {
		t.Fatalf("target_user detail = %#v, want %s", got, testMasterUserTargetAccount)
	}
}

func customObserveTLSSnapshot() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    74,
		Mode:          "observe",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: customObserveTLSStagePlan(),
			},
		},
	}
}

func schedulerGuardTLSSnapshot(mode string) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    80,
		Mode:          mode,
		DefaultPolicy: policy.BuiltinDefaultSet,
		SchedulerGuards: map[string]policyruntime.CompiledSchedulerGuard{
			testSchedulerGuardInsecure: {
				Root: policyruntime.CompiledExpr{
					Kind:        policyruntime.ExprKindAttribute,
					AttributeID: policy.AttributeRequestConnectionTLS,
					Operator:    "is",
					Expected:    policyruntime.TypedValue{Value: false},
				},
				OnMissingAttribute: "run",
			},
		},
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       definitions.ControlTLSEncryption,
							Type:       policy.CheckTypeTLSEncryption,
							ConfigRef:  policyConfigRefTLS,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
							SkipIf:     []string{testSchedulerGuardInsecure},
						},
					},
				},
			},
		},
	}
}

func customEnforcePreAuthControlSnapshot() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    76,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       definitions.ControlBruteForce,
							Type:       policy.CheckTypeBruteForce,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
						customObserveTLSCheck(),
					},
					Policies: []policyruntime.CompiledPolicy{customBruteForceSkipPolicy()},
				},
			},
		},
	}
}

func customEnforceTLSSnapshot(compiled policyruntime.CompiledPolicy) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    75,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage:    policy.StagePreAuth,
					Checks:   []policyruntime.CompiledCheck{customObserveTLSCheck()},
					Policies: []policyruntime.CompiledPolicy{compiled},
				},
			},
		},
	}
}

func customObserveTLSStagePlan() policyruntime.CompiledStagePlan {
	return policyruntime.CompiledStagePlan{
		Stage:    policy.StagePreAuth,
		Checks:   []policyruntime.CompiledCheck{customObserveTLSCheck()},
		Policies: []policyruntime.CompiledPolicy{customObserveTLSDenyPolicy()},
	}
}

func customObserveTLSCheck() policyruntime.CompiledCheck {
	return policyruntime.CompiledCheck{
		Name:        definitions.ControlTLSEncryption,
		Type:        policy.CheckTypeTLSEncryption,
		Stage:       policy.StagePreAuth,
		Operations:  []policy.Operation{policy.OperationAuthenticate},
		RunIf:       policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
		ObserveSafe: true,
	}
}

func customObserveTLSDenyPolicy() policyruntime.CompiledPolicy {
	return policyruntime.CompiledPolicy{
		Name:          "custom_deny_tls",
		Stage:         policy.StagePreAuth,
		Operations:    []policy.Operation{policy.OperationAuthenticate},
		RequireChecks: []string{definitions.ControlTLSEncryption},
		Root: policyruntime.CompiledExpr{
			Kind:        policyruntime.ExprKindAttribute,
			AttributeID: policy.AttributeTLSSecure,
			Operator:    "is",
			Expected:    policyruntime.TypedValue{Value: false},
		},
		Then: policyruntime.DecisionPlan{
			Decision:       policy.DecisionDeny,
			OutcomeMarker:  "auth.outcome.custom_tls_deny",
			FSMEventMarker: policy.FSMEventMarkerPreAuthDeny,
			ResponseMarker: policy.ResponseMarkerFail,
		},
	}
}

func customEnforceTLSDenyPolicy(expected bool) policyruntime.CompiledPolicy {
	compiled := customObserveTLSDenyPolicy()
	compiled.Then.ResponseMessage = policyruntime.ResponseMessagePlan{
		Source:  policy.ResponseSourceLiteral,
		Literal: "Custom TLS deny",
	}
	compiled.Root.Expected = policyruntime.TypedValue{Value: expected}

	return compiled
}

func customBruteForceSkipPolicy() policyruntime.CompiledPolicy {
	return policyruntime.CompiledPolicy{
		Name:          "custom_brute_force_skip",
		Stage:         policy.StagePreAuth,
		Operations:    []policy.Operation{policy.OperationAuthenticate},
		RequireChecks: []string{definitions.ControlBruteForce},
		Root: policyruntime.CompiledExpr{
			Kind:        policyruntime.ExprKindAttribute,
			AttributeID: policy.AttributeBruteForceTriggered,
			Operator:    "is",
			Expected:    policyruntime.TypedValue{Value: true},
		},
		Then: policyruntime.DecisionPlan{
			Decision:       policy.DecisionNeutral,
			OutcomeMarker:  "auth.outcome.custom_brute_force_skip",
			FSMEventMarker: policy.FSMEventMarkerPreAuthOK,
			Control:        policyruntime.DecisionControl{SkipRemainingStageChecks: true},
		},
	}
}

func activatePolicySnapshotForTest(t *testing.T, snapshot *policyruntime.Snapshot) {
	t.Helper()

	store := policyruntime.DefaultStore()

	previous := store.Active()
	if err := store.Activate(snapshot); err != nil {
		t.Fatalf("activate policy snapshot: %v", err)
	}

	t.Cleanup(func() {
		if previous == nil {
			previous = &policyruntime.Snapshot{}
		}

		if err := store.Activate(previous); err != nil {
			t.Fatalf("restore policy snapshot: %v", err)
		}
	})
}

func policyDecisionContext(ctx interface {
	Get(any) (any, bool)
}) (*policycollection.DecisionContext, bool) {
	value, ok := ctx.Get(policyCollectionContextKey)
	if !ok {
		return nil, false
	}

	policyCtx, ok := value.(*policycollection.DecisionContext)

	return policyCtx, ok
}

type recordingPluginEnvironmentBridge struct {
	err       error
	calls     int
	triggered bool
	abort     bool
}

func (b *recordingPluginEnvironmentBridge) Evaluate(
	ctx *gin.Context,
	view *StateView,
) (triggered bool, abort bool, handled bool, err error) {
	b.calls++
	auth := view.Auth()
	check := auth.beginPolicyCheck(ctx, policycollection.CheckSelector{
		CheckType: policy.CheckTypePluginEnvironment,
		Stage:     policy.StagePreAuth,
		ConfigRef: testPluginEnvironmentConfigRef,
	})
	auth.finishPolicyCheck(check, policyCheckResult{
		Err:          b.err,
		Status:       policy.CheckStatusOK,
		Matched:      b.triggered,
		DecisionHint: policyDecision(b.triggered, policy.DecisionDeny),
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(
				"auth.plugin.environment.geoip.environment.triggered",
				policy.StagePreAuth,
				auth.policyOperation(),
				b.triggered,
				nil,
			),
		},
	})

	return b.triggered, b.abort, true, b.err
}
