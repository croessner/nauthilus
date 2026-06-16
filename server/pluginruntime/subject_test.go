package pluginruntime

import (
	"context"
	"testing"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
)

const (
	subjectBackendName    = "imap-a"
	subjectBackendIP      = "192.0.2.10"
	subjectTestName       = "subject"
	subjectCheckConfigRef = pluginSubjectConfigRefPrefix + backendTestModuleName + "." + subjectTestName
	subjectCheckName      = "plugin_subject_customer_subject"
	subjectFlagAttribute  = "plugin.customer.subject.flag"
	subjectRiskAttribute  = "plugin.customer.subject.risk"
	subjectSourceFirst    = "first"
	subjectSourceSecond   = "second"
	subjectStaleAttr      = "stale"
	subjectStaleContext   = "stale_context"
	subjectStatusKey      = "auth.plugin.subject"
	subjectStatusText     = "native subject ok"
	subjectTestQualified  = backendTestModuleName + "." + subjectTestName
	subjectTierAttr       = "tier"
	subjectTierGold       = "gold"
	subjectTierSilver     = "silver"
)

func TestSubjectSourceReceivesBackendResultAndAppliesOutputs(t *testing.T) {
	source := &fakeSubjectSource{
		result: pluginapi.SubjectResult{
			Status: &pluginapi.StatusMessage{
				MessageKey:  subjectStatusKey,
				DefaultText: subjectStatusText,
			},
			Logs: []pluginapi.LogField{{Key: "subject_marker", Value: "native"}},
			Facts: []pluginapi.PolicyFact{
				{Attribute: subjectRiskAttribute, Value: float64(0.7)},
			},
			BackendAttributes: pluginapi.AttributePatch{
				Set: map[string][]string{
					backendTestMailAttr: {backendTestMail},
				},
				Delete: []string{subjectStaleAttr},
			},
			RuntimeDelta: pluginapi.RuntimeDelta{
				Set:    map[string]any{"plugin.subject.risk": float64(0.7)},
				Delete: []string{subjectStaleContext},
			},
			SelectedBackend: &pluginapi.BackendServerRef{
				Name:     subjectBackendName,
				Protocol: "imap",
				Address:  subjectBackendIP,
				Port:     "993",
			},
		},
	}
	bridge := newSubjectTestBridge(t, source)
	auth := newSubjectTestAuth(t)
	auth.Runtime.Context.Set(subjectStaleContext, "remove-me")

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t, subjectRiskAttribute)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled {
		t.Fatal("Analyze() handled = false, want true")
	}

	if got != definitions.AuthResultOK {
		t.Fatalf("Analyze() = %v, want OK", got)
	}

	assertSubjectBackendRequest(t, source.lastRequest)
	assertSubjectAttributes(t, auth, passDBResult)
	assertSubjectRuntime(t, auth, passDBResult)

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()
	if value := report.Attributes[subjectRiskAttribute].Value; value != float64(0.7) {
		t.Fatalf("policy fact = %#v, want 0.7", value)
	}

	if check := report.Checks[subjectCheckName]; check.Type != policy.CheckTypePluginSubjectSource || check.Matched {
		t.Fatalf("subject check = %#v, want neutral plugin subject check", check)
	}
}

// assertSubjectBackendRequest verifies the subject source received the mapped backend result.
func assertSubjectBackendRequest(t *testing.T, request pluginapi.SubjectRequest) {
	t.Helper()

	if request.BackendResult.Account != backendTestAccount || !request.BackendResult.Authenticated {
		t.Fatalf("backend result request = %#v, want authenticated %s", request.BackendResult, backendTestAccount)
	}
}

// assertSubjectAttributes verifies attribute patches reached both auth and backend result state.
func assertSubjectAttributes(t *testing.T, auth *core.AuthState, passDBResult *core.PassDBResult) {
	t.Helper()

	if got := firstStringAttribute(passDBResult.Attributes[backendTestMailAttr]); got != backendTestMail {
		t.Fatalf("mail attribute = %q, want %s", got, backendTestMail)
	}

	if _, ok := passDBResult.Attributes[subjectStaleAttr]; ok {
		t.Fatal("stale attribute still present after delete patch")
	}

	if got := firstStringAttributeFromAuth(auth, backendTestMailAttr); got != backendTestMail {
		t.Fatalf("auth mail attribute = %q, want %s", got, backendTestMail)
	}

	if _, ok := auth.GetAttribute(subjectStaleAttr); ok {
		t.Fatal("auth stale attribute still present after delete patch")
	}
}

// assertSubjectRuntime verifies runtime context, status, and backend selection updates.
func assertSubjectRuntime(t *testing.T, auth *core.AuthState, passDBResult *core.PassDBResult) {
	t.Helper()

	if value := auth.Runtime.Context.Get(subjectStaleContext); value != nil {
		t.Fatalf("stale_context = %#v, want nil", value)
	}

	if value := auth.Runtime.Context.Get("plugin.subject.risk"); value != float64(0.7) {
		t.Fatalf("plugin.subject.risk = %#v, want 0.7", value)
	}

	if auth.Runtime.StatusMessage != subjectStatusText || auth.Runtime.StatusMessageI18NKey != subjectStatusKey {
		t.Fatalf("status = %q/%q, want plugin status", auth.Runtime.StatusMessage, auth.Runtime.StatusMessageI18NKey)
	}

	if auth.Runtime.UsedBackendIP != subjectBackendIP || auth.Runtime.UsedBackendPort != 993 {
		t.Fatalf("selected backend = %s:%d, want %s:993", auth.Runtime.UsedBackendIP, auth.Runtime.UsedBackendPort, subjectBackendIP)
	}

	if passDBResult.BackendRef.Name != subjectBackendName {
		t.Fatalf("backend ref = %#v, want selected plugin backend ref", passDBResult.BackendRef)
	}
}

func TestSubjectSourceRejectionMapsToFailure(t *testing.T) {
	bridge := newSubjectTestBridge(t, &fakeSubjectSource{
		result: pluginapi.SubjectResult{
			Status:   &pluginapi.StatusMessage{DefaultText: "subject rejected"},
			Rejected: true,
		},
	})
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled {
		t.Fatal("Analyze() handled = false, want true")
	}

	if got != definitions.AuthResultFail || auth.Runtime.Authorized {
		t.Fatalf("Analyze() = %v authorized=%t, want fail/false", got, auth.Runtime.Authorized)
	}
}

func TestSubjectSourcePreservesExistingFailure(t *testing.T) {
	bridge := newSubjectTestBridge(t, &fakeSubjectSource{})
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultFail)
	if !handled {
		t.Fatal("Analyze() handled = false, want true")
	}

	if got != definitions.AuthResultFail || auth.Runtime.Authorized {
		t.Fatalf("Analyze() = %v authorized=%t, want existing fail/false", got, auth.Runtime.Authorized)
	}
}

func TestSubjectSourceMergeOrderIsDeterministic(t *testing.T) {
	first := &fakeSubjectSource{
		name: subjectSourceFirst,
		result: pluginapi.SubjectResult{
			BackendAttributes: pluginapi.AttributePatch{Set: map[string][]string{subjectTierAttr: {subjectTierSilver}}},
			RuntimeDelta:      pluginapi.RuntimeDelta{Set: map[string]any{subjectTierAttr: subjectTierSilver}},
		},
	}
	second := &fakeSubjectSource{
		name: subjectSourceSecond,
		result: pluginapi.SubjectResult{
			BackendAttributes: pluginapi.AttributePatch{Set: map[string][]string{subjectTierAttr: {subjectTierGold}}},
			RuntimeDelta:      pluginapi.RuntimeDelta{Set: map[string]any{subjectTierAttr: subjectTierGold}},
		},
	}
	bridge := newSubjectTestBridge(t, first, second)
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled || got != definitions.AuthResultOK {
		t.Fatalf("Analyze() = %v handled=%t, want OK/true", got, handled)
	}

	if got := firstStringAttribute(passDBResult.Attributes[subjectTierAttr]); got != subjectTierGold {
		t.Fatalf("tier attribute = %q, want %s", got, subjectTierGold)
	}

	if got := auth.Runtime.Context.Get(subjectTierAttr); got != subjectTierGold {
		t.Fatalf("runtime tier = %#v, want %s", got, subjectTierGold)
	}
}

func TestSubjectSourceUnknownPolicyFactFailsSafely(t *testing.T) {
	bridge := newSubjectTestBridge(t, &fakeSubjectSource{
		result: pluginapi.SubjectResult{
			Facts: []pluginapi.PolicyFact{{Attribute: "plugin.customer.subject.unknown", Value: true}},
		},
	})
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled {
		t.Fatal("Analyze() handled = false, want true")
	}

	if got != definitions.AuthResultTempFail || auth.Runtime.Authorized {
		t.Fatalf("Analyze() = %v authorized=%t, want tempfail/false", got, auth.Runtime.Authorized)
	}
}

func newSubjectTestBridge(t *testing.T, sources ...*fakeSubjectSource) *SubjectSourceBridge {
	t.Helper()

	module := config.PluginModule{
		Name: backendTestModuleName,
		Type: config.PluginModuleTypeGo,
		Path: "/plugins/customer.so",
	}

	runner := newStartedTestRunnerWithModule(t, &runtimePlugin{}, module, func(registrar pluginapi.Registrar) error {
		for _, source := range sources {
			if err := registrar.RegisterSubjectSource(source); err != nil {
				return err
			}
		}

		return nil
	})

	return NewSubjectSourceBridge(runner)
}

func newSubjectTestAuth(t *testing.T) *core.AuthState {
	t.Helper()

	auth := newBackendTestAuth(t)
	auth.Runtime.Context = lualib.NewContext()

	return auth
}

func newSubjectTestPassDBResult() *core.PassDBResult {
	passDBResult := core.GetPassDBResultFromPool()
	passDBResult.Authenticated = true
	passDBResult.UserFound = true
	passDBResult.Account = backendTestAccount
	passDBResult.AccountField = backendTestUIDAttr
	passDBResult.Backend = definitions.BackendPlugin
	passDBResult.BackendName = backendTestQualified
	passDBResult.Attributes = bktype.AttributeMapping{
		backendTestUIDAttr: {backendTestAccount},
		subjectStaleAttr:   {"remove-me"},
	}

	return passDBResult
}

func activateSubjectPolicySnapshot(t *testing.T, attributes ...string) {
	t.Helper()

	activatePluginPolicySnapshot(t, pluginPolicySnapshotSpec{
		stage:         policy.StageSubjectAnalysis,
		category:      policyregistry.AttributeCategorySubject,
		attributeType: policyregistry.AttributeTypeNumber,
		checkName:     subjectCheckName,
		checkType:     policy.CheckTypePluginSubjectSource,
		configRef:     subjectCheckConfigRef,
	}, attributes...)
}

func firstStringAttributeFromAuth(auth *core.AuthState, name string) string {
	values, _ := auth.GetAttribute(name)

	return firstStringAttribute(values)
}

type fakeSubjectSource struct {
	lastRequest pluginapi.SubjectRequest
	result      pluginapi.SubjectResult
	name        string
}

func (s *fakeSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	name := s.name
	if name == "" {
		name = subjectTestName
	}

	return pluginapi.SourceDescriptor{
		Name:        name,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

func (s *fakeSubjectSource) Evaluate(_ context.Context, request pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
	s.lastRequest = request

	return s.result, nil
}
