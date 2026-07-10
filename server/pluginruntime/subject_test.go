package pluginruntime

import (
	"context"
	"errors"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
)

const (
	subjectBackendName           = "imap-a"
	subjectBackendIP             = "192.0.2.10"
	subjectExampleCheckConfigRef = pluginSubjectConfigRefPrefix + "example_auth.subject"
	subjectExampleCheckName      = "plugin_subject_example_auth_policy"
	subjectExampleModuleName     = "example_auth"
	subjectExampleRejectedAttr   = "auth.plugin.subject.example_auth.policy.rejected"
	subjectExampleErrorAttr      = "auth.plugin.subject.example_auth.policy.error"
	subjectExampleSourceName     = "policy"
	subjectTestName              = "subject"
	subjectCheckConfigRef        = pluginSubjectConfigRefPrefix + backendTestModuleName + "." + subjectTestName
	subjectCheckName             = "plugin_subject_customer_subject"
	subjectFlagAttribute         = "plugin.customer.subject.flag"
	subjectRiskAttribute         = "plugin.customer.subject.risk"
	subjectSourceFirst           = "first"
	subjectSourceSecond          = "second"
	subjectStaleAttr             = "stale"
	subjectStaleContext          = "stale_context"
	subjectStatusKey             = "auth.plugin.subject"
	subjectStatusText            = "native subject ok"
	subjectTestQualified         = backendTestModuleName + "." + subjectTestName
	subjectTierAttr              = "tier"
	subjectTierGold              = "gold"
	subjectTierSilver            = "silver"
	responseMutationHeader       = "X-Nauthilus-Protection"
	responseMutationStepupValue  = "stepup"
	responseMutationReasonHeader = "X-Nauthilus-Protection-Reason"
	responseMutationThreshold    = "threshold"
	subjectUniqueIDField         = "entryUUID"
	subjectDisplayNameField      = "displayName"
	subjectTOTPSecretField       = "totpSecret"
	subjectTOTPRecoveryField     = "totpRecovery"
	subjectGroup                 = "group-a"
	subjectGroupDN               = "cn=group-a,dc=example,dc=test"
)

func TestSubjectSourceReceivesSafeIdentityReadbackWithoutStatusOrFacts(t *testing.T) {
	source := newIdentityReadbackSubjectSource()
	bridge := newSubjectTestBridge(t, source)
	auth := newSubjectTestAuth(t)
	auth.Runtime.StatusMessage = "internal status"
	auth.Runtime.AccountProviderPluginFacts = []pluginapi.PolicyFact{{Attribute: subjectRiskAttribute, Value: float64(0.4)}}

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	passDBResult.UniqueUserIDField = subjectUniqueIDField
	passDBResult.DisplayNameField = subjectDisplayNameField
	passDBResult.TOTPSecretField = subjectTOTPSecretField
	passDBResult.TOTPRecoveryField = subjectTOTPRecoveryField
	passDBResult.Groups = []string{subjectGroup}
	passDBResult.GroupDistinguishedNames = []string{subjectGroupDN}
	passDBResult.BackendRef = core.RemoteBackendRef{
		Name:        "authority-backend",
		Protocol:    "imap",
		Authority:   "authority-a",
		OpaqueToken: "192.0.2.44:993",
	}
	passDBResult.AdditionalAttributes = map[string]any{
		"plugin_status": "must not be reconstructed",
		"plugin_facts":  []string{"must not be reconstructed"},
	}

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled || got != definitions.AuthResultOK {
		t.Fatalf("Analyze() = %v handled=%t, want OK/true", got, handled)
	}

	requestResult := source.lastRequest.BackendResult
	assertSubjectIdentity(t, requestResult.Identity)

	if requestResult.Status != nil || len(requestResult.Facts) != 0 {
		t.Fatalf("reverse status/facts = %#v/%#v, want nil/empty", requestResult.Status, requestResult.Facts)
	}

	if requestResult.BackendServer == nil || requestResult.BackendServer.Name != "authority-backend" || requestResult.BackendServer.Address != "192.0.2.44" {
		t.Fatalf("backend readback = %#v, want authority backend", requestResult.BackendServer)
	}

	assertPassDBIdentity(t, passDBResult)

	if passDBResult.BackendRef.Name != "selected-subject-backend" {
		t.Fatalf("selected backend = %#v, want subject patch output", passDBResult.BackendRef)
	}
}

func TestParallelSubjectRequestsOwnIndependentIdentityState(t *testing.T) {
	firstMutated := make(chan struct{})
	secondObservedOriginal := false
	first := newFirstMutatingSubjectSource(firstMutated)
	second := newSecondMutatingSubjectSource(firstMutated, &secondObservedOriginal)
	bridge := newSubjectTestBridge(t, first, second)
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	passDBResult.UniqueUserIDField = subjectUniqueIDField
	passDBResult.DisplayNameField = subjectDisplayNameField
	passDBResult.TOTPSecretField = subjectTOTPSecretField
	passDBResult.TOTPRecoveryField = subjectTOTPRecoveryField
	passDBResult.Groups = []string{subjectGroup}
	passDBResult.GroupDistinguishedNames = []string{subjectGroupDN}

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled || got != definitions.AuthResultOK {
		t.Fatalf("Analyze() = %v handled=%t, want OK/true", got, handled)
	}

	if !secondObservedOriginal {
		t.Fatal("second parallel subject request observed sibling mutations")
	}

	if first.lastRequest.BackendResult.Attributes[backendTestUIDAttr][0] != "first-account" ||
		first.lastRequest.BackendResult.Identity.Groups[0] != "first-group" ||
		first.lastRequest.BackendResult.Identity.GroupDistinguishedNames[0] != "cn=first,dc=example,dc=test" {
		t.Fatalf("first request changed after sibling mutation: %#v", first.lastRequest.BackendResult)
	}

	if firstStringAttribute(passDBResult.Attributes[backendTestUIDAttr]) != backendTestAccount ||
		passDBResult.Groups[0] != subjectGroup || passDBResult.GroupDistinguishedNames[0] != subjectGroupDN {
		t.Fatalf("retained core result was mutated: %#v", passDBResult)
	}
}

// newIdentityReadbackSubjectSource returns a source that exercises every allowed patch field.
func newIdentityReadbackSubjectSource() *fakeSubjectSource {
	authenticated := true
	userFound := true

	return &fakeSubjectSource{result: pluginapi.SubjectResult{
		BackendResultPatch: &pluginapi.BackendResultPatch{
			SelectedBackend: &pluginapi.BackendServerRef{
				Name:     "selected-subject-backend",
				Protocol: "imap",
				Address:  "192.0.2.55",
				Port:     "993",
			},
			Attributes: pluginapi.AttributePatch{Set: map[string][]string{
				backendTestMailAttr: {backendTestMail},
			}},
			Authenticated: &authenticated,
			UserFound:     &userFound,
			Account:       backendTestMail,
			AccountField:  backendTestMailAttr,
		},
	}}
}

// newFirstMutatingSubjectSource returns a source that mutates its private request copy.
func newFirstMutatingSubjectSource(firstMutated chan<- struct{}) *fakeSubjectSource {
	return &fakeSubjectSource{
		name: subjectSourceFirst,
		evaluate: func(_ context.Context, request pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
			mutateSubjectRequestIdentity(request, "first-account", "first-group", "cn=first,dc=example,dc=test")
			close(firstMutated)

			return pluginapi.SubjectResult{}, nil
		},
	}
}

// newSecondMutatingSubjectSource verifies sibling isolation before mutating its request copy.
func newSecondMutatingSubjectSource(firstMutated <-chan struct{}, observedOriginal *bool) *fakeSubjectSource {
	return &fakeSubjectSource{
		name: subjectSourceSecond,
		evaluate: func(_ context.Context, request pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
			<-firstMutated

			*observedOriginal = subjectRequestHasOriginalIdentity(request)
			mutateSubjectRequestIdentity(request, "second-account", "second-group", "cn=second,dc=example,dc=test")

			return pluginapi.SubjectResult{}, nil
		},
	}
}

// subjectRequestHasOriginalIdentity reports whether a sibling received the retained core values.
func subjectRequestHasOriginalIdentity(request pluginapi.SubjectRequest) bool {
	return request.BackendResult.Attributes[backendTestUIDAttr][0] == backendTestAccount &&
		len(request.BackendResult.Identity.Groups) == 1 && request.BackendResult.Identity.Groups[0] == subjectGroup &&
		len(request.BackendResult.Identity.GroupDistinguishedNames) == 1 && request.BackendResult.Identity.GroupDistinguishedNames[0] == subjectGroupDN
}

// mutateSubjectRequestIdentity changes every mutable identity collection in one request copy.
func mutateSubjectRequestIdentity(request pluginapi.SubjectRequest, account string, group string, groupDN string) {
	request.BackendResult.Attributes[backendTestUIDAttr][0] = account
	request.BackendResult.Identity.Groups[0] = group
	request.BackendResult.Identity.GroupDistinguishedNames[0] = groupDN
}

// assertSubjectIdentity verifies the complete safe identity readback value.
func assertSubjectIdentity(t *testing.T, identity pluginapi.BackendIdentityResult) {
	t.Helper()

	if identity.UniqueUserIDField != subjectUniqueIDField || identity.DisplayNameField != subjectDisplayNameField ||
		identity.TOTPSecretField != subjectTOTPSecretField || identity.TOTPRecoveryField != subjectTOTPRecoveryField ||
		len(identity.Groups) != 1 || identity.Groups[0] != subjectGroup ||
		len(identity.GroupDistinguishedNames) != 1 || identity.GroupDistinguishedNames[0] != subjectGroupDN {
		t.Fatalf("identity readback = %#v, want complete safe identity", identity)
	}
}

// assertPassDBIdentity verifies allowed patches leave core identity metadata unchanged.
func assertPassDBIdentity(t *testing.T, result *core.PassDBResult) {
	t.Helper()

	assertSubjectIdentity(t, pluginapi.BackendIdentityResult{
		UniqueUserIDField:       result.UniqueUserIDField,
		DisplayNameField:        result.DisplayNameField,
		TOTPSecretField:         result.TOTPSecretField,
		TOTPRecoveryField:       result.TOTPRecoveryField,
		Groups:                  result.Groups,
		GroupDistinguishedNames: result.GroupDistinguishedNames,
	})
}

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

func TestSubjectSourceBackendResultPatchUpdatesPassDBResult(t *testing.T) {
	authenticated := false
	userFound := true
	source := &fakeSubjectSource{
		result: pluginapi.SubjectResult{
			BackendResultPatch: &pluginapi.BackendResultPatch{
				Account:       backendTestMail,
				AccountField:  backendTestMailAttr,
				Authenticated: &authenticated,
				UserFound:     &userFound,
				Attributes: pluginapi.AttributePatch{
					Set: map[string][]string{
						backendTestMailAttr: {backendTestMail},
					},
					Delete: []string{backendTestUIDAttr},
				},
			},
		},
	}
	bridge := newSubjectTestBridge(t, source)
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled || got != definitions.AuthResultOK {
		t.Fatalf("Analyze() = %v handled=%t, want OK/true", got, handled)
	}

	if passDBResult.Account != backendTestMail || passDBResult.AccountField != backendTestMailAttr {
		t.Fatalf("patched account = %q/%q, want %q/%q", passDBResult.Account, passDBResult.AccountField, backendTestMail, backendTestMailAttr)
	}

	if passDBResult.Authenticated || !passDBResult.UserFound {
		t.Fatalf("patched flags = authenticated:%t user_found:%t, want false/true", passDBResult.Authenticated, passDBResult.UserFound)
	}

	if got := firstStringAttribute(passDBResult.Attributes[backendTestMailAttr]); got != backendTestMail {
		t.Fatalf("patched account attribute = %q, want %s", got, backendTestMail)
	}

	if _, ok := passDBResult.Attributes[backendTestUIDAttr]; ok {
		t.Fatalf("deleted account attribute %q still present", backendTestUIDAttr)
	}
}

func TestSubjectSourceBackendResultPatchFeedsLaterSubjectSource(t *testing.T) {
	first := &fakeSubjectSource{
		name: subjectSourceFirst,
		result: pluginapi.SubjectResult{
			BackendResultPatch: &pluginapi.BackendResultPatch{
				Account:      backendTestMail,
				AccountField: backendTestMailAttr,
			},
		},
	}
	second := &fakeSubjectSource{
		name:  subjectSourceSecond,
		after: []string{subjectSourceFirst},
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

	if second.lastRequest.BackendResult.Account != backendTestMail ||
		second.lastRequest.BackendResult.AccountField != backendTestMailAttr {
		t.Fatalf(
			"second source backend result = %q/%q, want %q/%q",
			second.lastRequest.BackendResult.Account,
			second.lastRequest.BackendResult.AccountField,
			backendTestMail,
			backendTestMailAttr,
		)
	}
}

func TestSubjectSourceAppliesResponseMutationHeaders(t *testing.T) {
	source := &fakeSubjectSource{
		result: pluginapi.SubjectResult{
			Status: &pluginapi.StatusMessage{DefaultText: subjectStatusText},
			Response: pluginapi.ResponseMutation{
				Headers: pluginapi.ResponseHeaderMutation{
					Set: map[string][]string{
						responseMutationHeader:       {responseMutationStepupValue},
						responseMutationReasonHeader: {responseMutationThreshold},
					},
				},
				StatusHeader: true,
			},
		},
	}
	bridge := newSubjectTestBridge(t, source)
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled || got != definitions.AuthResultOK {
		t.Fatalf("Analyze() = %v handled=%t, want OK/true", got, handled)
	}

	header := auth.Request.HTTPClientContext.Writer.Header()
	if got := header.Get(responseMutationHeader); got != responseMutationStepupValue {
		t.Fatalf("%s = %q, want stepup", responseMutationHeader, got)
	}

	if got := header.Get(responseMutationReasonHeader); got != responseMutationThreshold {
		t.Fatalf("%s = %q, want threshold", responseMutationReasonHeader, got)
	}

	if got := header.Get("Auth-Status"); got != subjectStatusText {
		t.Fatalf("Auth-Status = %q, want subject status", got)
	}
}

func TestSubjectSourceResponseMutationDuplicateHeaderLastSourceWins(t *testing.T) {
	first := &fakeSubjectSource{
		name: subjectSourceFirst,
		result: pluginapi.SubjectResult{
			Response: pluginapi.ResponseMutation{
				Headers: pluginapi.ResponseHeaderMutation{
					Set: map[string][]string{responseMutationHeader: {subjectSourceFirst}},
				},
			},
		},
	}
	second := &fakeSubjectSource{
		name: subjectSourceSecond,
		result: pluginapi.SubjectResult{
			Response: pluginapi.ResponseMutation{
				Headers: pluginapi.ResponseHeaderMutation{
					Set: map[string][]string{responseMutationHeader: {subjectSourceSecond}},
				},
			},
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

	if values := auth.Request.HTTPClientContext.Writer.Header().Values(responseMutationHeader); len(values) != 1 || values[0] != subjectSourceSecond {
		t.Fatalf("%s values = %#v, want [second]", responseMutationHeader, values)
	}
}

func TestSubjectSourceSelectsHostBackendCandidate(t *testing.T) {
	source := &candidateSelectingSubjectSource{}
	host := NewHost(WithBackendServers(NewBackendServerFacade(func() []*config.BackendServer {
		return []*config.BackendServer{
			{
				Protocol:  "imap",
				Host:      subjectBackendIP,
				Port:      993,
				HAProxyV2: true,
			},
		}
	})))
	bridge := newCandidateSubjectTestBridge(t, host, source)
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled || got != definitions.AuthResultOK {
		t.Fatalf("Analyze() = %v handled=%t, want OK/true", got, handled)
	}

	if !source.sawCandidate {
		t.Fatal("subject source did not observe backend candidates")
	}

	if auth.Runtime.UsedBackendIP != subjectBackendIP || auth.Runtime.UsedBackendPort != 993 {
		t.Fatalf("selected backend = %s:%d, want %s:993", auth.Runtime.UsedBackendIP, auth.Runtime.UsedBackendPort, subjectBackendIP)
	}

	if passDBResult.BackendRef.OpaqueToken != subjectBackendIP+":993" {
		t.Fatalf("backend ref token = %q, want selected candidate token", passDBResult.BackendRef.OpaqueToken)
	}

	if auth.Runtime.RemoteBackendRef.OpaqueToken != subjectBackendIP+":993" {
		t.Fatalf("runtime remote backend ref = %#v, want selected candidate", auth.Runtime.RemoteBackendRef)
	}
}

func TestSubjectSourceEmptyBackendCandidatesCanTempFail(t *testing.T) {
	source := &candidateSelectingSubjectSource{tempfailOnEmpty: true}
	host := NewHost(WithBackendServers(NewBackendServerFacade(func() []*config.BackendServer {
		return nil
	})))
	bridge := newCandidateSubjectTestBridge(t, host, source)
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activateSubjectPolicySnapshot(t)

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled || got != definitions.AuthResultTempFail {
		t.Fatalf("Analyze() = %v handled=%t, want tempfail/true", got, handled)
	}
}

// assertSubjectBackendRequest verifies the subject source received the mapped backend result.
func assertSubjectBackendRequest(t *testing.T, request pluginapi.SubjectRequest) {
	t.Helper()

	if request.BackendResult.Account != backendTestAccount || !request.BackendResult.Authenticated {
		t.Fatalf("backend result request = %#v, want authenticated %s", request.BackendResult, backendTestAccount)
	}

	if request.BackendResult.AccountField != backendTestUIDAttr {
		t.Fatalf("backend result account field = %q, want %s", request.BackendResult.AccountField, backendTestUIDAttr)
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

	if len(auth.Runtime.AdditionalLogs) != 2 ||
		auth.Runtime.AdditionalLogs[0] != "subject_marker" ||
		auth.Runtime.AdditionalLogs[1] != "native" {
		t.Fatalf("additional logs = %#v, want subject marker", auth.Runtime.AdditionalLogs)
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

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()
	if value := report.Attributes[policy.PluginSubjectAttributeID(backendTestModuleName, subjectTestName, "rejected")].Value; value != true {
		t.Fatalf("rejected attribute = %#v, want true", value)
	}

	check := report.Checks[subjectCheckName]
	if !check.Matched || check.DecisionHint != policy.DecisionDeny {
		t.Fatalf("subject check = %#v, want matched deny hint", check)
	}
}

func TestSubjectSourceErrorMapsToTempfailWithoutRejection(t *testing.T) {
	bridge := newSubjectTestBridge(t, &fakeSubjectSource{err: errors.New("subject source failed")})
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

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()
	if value := report.Attributes[policy.PluginSubjectAttributeID(backendTestModuleName, subjectTestName, "rejected")].Value; value != false {
		t.Fatalf("rejected attribute = %#v, want false", value)
	}

	if value := report.Attributes[policy.PluginSubjectAttributeID(backendTestModuleName, subjectTestName, "error")].Value; value != true {
		t.Fatalf("error attribute = %#v, want true", value)
	}

	check := report.Checks[subjectCheckName]
	if !check.Matched || check.DecisionHint != policy.DecisionTempFail {
		t.Fatalf("subject check = %#v, want matched tempfail hint", check)
	}
}

func TestSubjectSourceRecordsCanonicalGeneratedAttributes(t *testing.T) {
	bridge := newSubjectTestBridgeForModule(t, subjectExampleModuleName, &fakeSubjectSource{
		name: subjectExampleSourceName,
		result: pluginapi.SubjectResult{
			Rejected: true,
		},
		err: errors.New("subject source failed"),
	})
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activatePluginPolicySnapshot(t, pluginPolicySnapshotSpec{
		stage:         policy.StageSubjectAnalysis,
		category:      policyregistry.AttributeCategorySubject,
		attributeType: policyregistry.AttributeTypeBool,
		checkName:     subjectExampleCheckName,
		checkType:     policy.CheckTypePluginSubjectSource,
		configRef:     subjectExampleCheckConfigRef,
	})

	got, handled := bridge.Analyze(auth.Request.HTTPClientContext, auth.View(), passDBResult, definitions.AuthResultOK)
	if !handled {
		t.Fatal("Analyze() handled = false, want true")
	}

	if got != definitions.AuthResultTempFail {
		t.Fatalf("Analyze() = %v, want tempfail from subject source error", got)
	}

	report := auth.PolicyDecisionContext(auth.Request.HTTPClientContext).Report()
	if value := report.Attributes[subjectExampleRejectedAttr].Value; value != false {
		t.Fatalf("rejected attribute = %#v, want false when the subject source errors", value)
	}

	if value := report.Attributes[subjectExampleErrorAttr].Value; value != true {
		t.Fatalf("error attribute = %#v, want true", value)
	}

	check := report.Checks[subjectExampleCheckName]
	if check.Type != policy.CheckTypePluginSubjectSource || !check.Matched {
		t.Fatalf("subject check = %#v, want matched plugin subject check", check)
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

func TestSubjectSourceWrongStagePolicyFactFailsSafely(t *testing.T) {
	bridge := newSubjectTestBridge(t, &fakeSubjectSource{
		result: pluginapi.SubjectResult{
			Facts: []pluginapi.PolicyFact{{Attribute: subjectFlagAttribute, Value: true}},
		},
	})
	auth := newSubjectTestAuth(t)

	passDBResult := newSubjectTestPassDBResult()
	defer core.PutPassDBResultToPool(passDBResult)

	activatePluginPolicySnapshot(t, pluginPolicySnapshotSpec{
		stage:         policy.StagePreAuth,
		category:      policyregistry.AttributeCategorySubject,
		attributeType: policyregistry.AttributeTypeBool,
		checkName:     environmentCheckName,
		checkType:     policy.CheckTypePluginEnvironment,
		configRef:     environmentCheckConfigRef,
	}, subjectFlagAttribute)

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

	return newSubjectTestBridgeForModule(t, backendTestModuleName, sources...)
}

// newSubjectTestBridgeForModule starts a subject bridge for one configured native plugin module.
func newSubjectTestBridgeForModule(
	t *testing.T,
	moduleName string,
	sources ...*fakeSubjectSource,
) *SubjectSourceBridge {
	t.Helper()

	module := config.PluginModule{
		Name: moduleName,
		Type: config.PluginModuleTypeGo,
		Path: "/plugins/" + moduleName + ".so",
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
	evaluate    func(context.Context, pluginapi.SubjectRequest) (pluginapi.SubjectResult, error)
	err         error
	after       []string
	name        string
}

func (s *fakeSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	name := s.name
	if name == "" {
		name = subjectTestName
	}

	return pluginapi.SourceDescriptor{
		Name:        name,
		After:       append([]string(nil), s.after...),
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

// Evaluate captures the request and delegates to an optional test-specific evaluator.
func (s *fakeSubjectSource) Evaluate(ctx context.Context, request pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
	s.lastRequest = request
	if s.evaluate != nil {
		return s.evaluate(ctx, request)
	}

	return s.result, s.err
}

// newCandidateSubjectTestBridge starts a subject bridge with a host-backed candidate source.
func newCandidateSubjectTestBridge(t *testing.T, host pluginapi.Host, source *candidateSelectingSubjectSource) *SubjectSourceBridge {
	t.Helper()

	plugin := &candidateSubjectPlugin{source: source}
	module := config.PluginModule{
		Name: backendTestModuleName,
		Type: config.PluginModuleTypeGo,
		Path: "/plugins/customer.so",
	}
	runner := newStartedTestRunnerWithModule(t, plugin, module, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterSubjectSource(source)
	}, WithHost(host))

	return NewSubjectSourceBridge(runner)
}

var errNoBackendCandidate = errors.New("no backend candidates")

type candidateSubjectPlugin struct {
	source *candidateSelectingSubjectSource
}

// Metadata returns static plugin metadata for the candidate source fixture.
func (p *candidateSubjectPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:       "candidate-subject",
		Version:    testRuntimePluginVersion,
		APIVersion: pluginapi.APIVersion,
	}
}

// Register leaves component registration to the test helper.
func (p *candidateSubjectPlugin) Register(pluginapi.Registrar) error {
	return nil
}

// Start gives the source access to the runtime host facade.
func (p *candidateSubjectPlugin) Start(_ context.Context, host pluginapi.Host) error {
	p.source.host = host

	return nil
}

// Stop releases the host reference captured by Start.
func (p *candidateSubjectPlugin) Stop(context.Context) error {
	p.source.host = nil

	return nil
}

type candidateSelectingSubjectSource struct {
	host            pluginapi.Host
	sawCandidate    bool
	tempfailOnEmpty bool
}

// Descriptor returns the subject source scheduling metadata.
func (s *candidateSelectingSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{
		Name:        subjectTestName,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

// Evaluate selects the first host-provided backend candidate.
func (s *candidateSelectingSubjectSource) Evaluate(ctx context.Context, request pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
	_ = request

	candidates := s.host.BackendServers().List(ctx)
	if len(candidates) == 0 {
		if s.tempfailOnEmpty {
			return pluginapi.SubjectResult{}, errNoBackendCandidate
		}

		return pluginapi.SubjectResult{Rejected: true}, nil
	}

	s.sawCandidate = true
	ref := candidates[0].Ref()

	return pluginapi.SubjectResult{SelectedBackend: &ref}, nil
}
