package main

import (
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// learningConfigMap extends the canonical example with conservative independent authentication signals.
func learningConfigMap(t *testing.T) map[string]any {
	t.Helper()
	raw := testConfigMap(t)

	fragment := testYAMLMap(t, "../../../server/docs/examples/reputation_authentication_catalog.yml")["config"].(map[string]any)
	for key, value := range fragment {
		raw[key] = value
	}

	return raw
}

// TestAuthLearningRejectsBroadOrDependentEvidence denies account poisoning, ASN spread and final Policy feedback.
func TestAuthLearningRejectsBroadOrDependentEvidence(t *testing.T) {
	mutations := []func(map[string]any){
		func(raw map[string]any) {
			raw["signals"].(map[string]any)["auth.bad_credentials"].(map[string]any)["subject_roles"].(map[string]any)["auth_account"] = map[string]any{"account": 1.0}
		},
		func(raw map[string]any) {
			raw["signals"].(map[string]any)["auth.success"].(map[string]any)["subject_roles"].(map[string]any)["auth_client"].(map[string]any)["asn"] = 0.1
		},
		func(raw map[string]any) {
			raw["signals"].(map[string]any)["auth.success"].(map[string]any)["evidence_origin"] = "post_policy"
		},
		func(raw map[string]any) {
			raw["auth_learning"].(map[string]any)["bad_credentials_signal"] = "auth.success"
		},
	}
	_, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)

	for _, mutate := range mutations {
		raw := learningConfigMap(t)
		mutate(raw)
		_, err := decodeConfig(pluginregistry.NewConfigView(raw))
		requireError(t, err)
	}
}

// TestAuthLearningProjectsOnlyBackendTruth ignores final flags, caller facts and externally supplied session IDs.
func TestAuthLearningProjectsOnlyBackendTruth(t *testing.T) {
	cfg, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)
	identity, err := pluginapi.NewExecutionIdentityView("reputation", "learn_outcome", "post_action", "enqueue", pluginapi.DecisionTargetSelector{Namespace: "authn", Action: "authenticate"})
	requireNoError(t, err)

	for _, status := range []pluginapi.BackendOutcomeStatus{pluginapi.BackendOutcomeAuthenticated, pluginapi.BackendOutcomeBadCredentials} {
		outcome, err := pluginapi.NewBackendOutcomeView("host-event", "verified-account", status, time.Now())
		requireNoError(t, err)
		request, err := pluginapi.NewPostActionRequest(pluginapi.PostActionRequest{BackendOutcome: outcome,
			Snapshot: pluginapi.RequestSnapshot{ClientIP: "192.0.2.7", Account: "forged-account", ExternalSessionID: "forged-event", Runtime: pluginapi.RuntimeFlags{Authenticated: status != pluginapi.BackendOutcomeAuthenticated}}}, identity)
		requireNoError(t, err)
		source, input, err := cfg.authenticationObservation(request)
		requireNoError(t, err)

		if source == nil || input.eventID != "host-event" {
			t.Fatal("host authority missing")
		}

		for _, subject := range input.subjects {
			if subject.kind == kindASN || (subject.kind == kindAccount && (status != pluginapi.BackendOutcomeAuthenticated || subject.value != "verified-account")) {
				t.Fatal("unsafe authentication subject")
			}
		}
	}

	_, _, err = cfg.authenticationObservation(pluginapi.PostActionRequest{})
	requireError(t, err)
}

// TestAuthLearningSkipsBackendHealthChecks prevents synthetic probes from creating reputation evidence.
func TestAuthLearningSkipsBackendHealthChecks(t *testing.T) {
	cfg, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)
	identity, err := pluginapi.NewExecutionIdentityView(pluginName, componentLearnOutcome, extensionPostAction, "enqueue", authenticationTarget)
	requireNoError(t, err)
	outcome, err := pluginapi.NewBackendOutcomeView("health-probe", "probe-account", pluginapi.BackendOutcomeAuthenticated, time.Now())
	requireNoError(t, err)
	request, err := pluginapi.NewPostActionRequest(pluginapi.PostActionRequest{BackendOutcome: outcome, Snapshot: pluginapi.RequestSnapshot{HealthCheck: true, ClientIP: "192.0.2.7"}}, identity)
	requireNoError(t, err)

	_, _, err = cfg.authenticationObservation(request)
	if err != errBackendUnobserved {
		t.Fatal("health check created reputation evidence")
	}
}

// TestAuthLearningMappingParticipatesInModelIdentity prevents changed host event semantics from sharing accumulator state.
func TestAuthLearningMappingParticipatesInModelIdentity(t *testing.T) {
	cfg, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)
	original, err := compileModel(cfg)
	requireNoError(t, err)

	cfg.raw.AuthLearning = nil
	changed, err := compileModel(cfg)
	requireNoError(t, err)

	if original.fingerprint == changed.fingerprint {
		t.Fatal("backend signal mapping missing from model identity")
	}
}

// TestAuthAssessmentAcceptsHostCanonicalFactIdentity keeps generic extractors compatible with real host-owned authentication facts.
func TestAuthAssessmentAcceptsHostCanonicalFactIdentity(t *testing.T) {
	raw := testConfigMap(t)
	raw["target_bindings"] = []any{map[string]any{"target": "authn/authenticate", "output_fact": "auth_subjects", "subjects": []any{map[string]any{"attribute": "nauthilus.request.client.ip", "category": "environment", "role": "auth_client", "kind": "ip"}}}}
	_, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
}
