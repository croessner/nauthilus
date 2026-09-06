package main

import (
	"context"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// testTagger uses the production opaque facade with a disposable non-secret test key.
func testTagger(t *testing.T) pluginapi.OpaqueIdentifierTagger {
	t.Helper()

	tagger, err := pluginruntime.NewOpaqueIdentifierTagger([]pluginruntime.OpaqueIdentifierScopeKeys{{
		Scope: "reputation-subject", Active: pluginruntime.OpaqueIdentifierKey{Version: "current", Secret: secret.New("0123456789abcdef0123456789abcdef")},
	}})
	requireNoError(t, err)

	return tagger
}

// testObservation returns fixed independent evidence suitable for deterministic admission tests.
func testObservation() observationInput {
	return observationInput{eventID: "event-1", signal: "scan.clean", observedAt: time.Unix(1800000000, 0).UTC(),
		subjects: []subjectInput{{role: "smtp_peer", kind: "ip", value: "192.0.2.3"}}}
}

// TestObservationBoundsAndDuplicates rejects complete malformed observations before any storage exists.
func TestObservationBoundsAndDuplicates(t *testing.T) {
	cfg := testConfig(t)
	tagger := testTagger(t)

	tests := []struct {
		name   string
		mutate func(*observationInput)
	}{
		{"empty event", func(v *observationInput) { v.eventID = "" }},
		{"unconfigured signal", func(v *observationInput) { v.signal = "scan.other" }},
		{"old", func(v *observationInput) { v.observedAt = v.observedAt.Add(-25 * time.Hour) }},
		{"future", func(v *observationInput) { v.observedAt = v.observedAt.Add(3 * time.Minute) }},
		{"magnitude high", func(v *observationInput) { n := 1.1; v.magnitude = &n }},
		{"unknown role", func(v *observationInput) { v.subjects[0].role = "account" }},
		{"forged network", func(v *observationInput) {
			v.subjects[0] = subjectInput{role: "smtp_peer", kind: "network", value: "192.0.2.0/24"}
		}},
		{"forged ASN", func(v *observationInput) {
			v.subjects[0] = subjectInput{role: "smtp_peer", kind: "asn", value: "64500"}
		}},
		{"alias duplicate", func(v *observationInput) {
			v.subjects = append(v.subjects, subjectInput{role: "smtp_peer", kind: "ip", value: "::ffff:192.0.2.3"})
		}},
		{"fanout", func(v *observationInput) {
			for len(v.subjects) < 9 {
				v.subjects = append(v.subjects, v.subjects[0])
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := testObservation()
			tt.mutate(&input)
			_, reason, err := cfg.admitObservation(context.Background(), cfg.apiSources["ScanWriter"], input, testObservation().observedAt, tagger, nil)
			requireNoError(t, err)

			if reason == reasonValid {
				t.Fatal("invalid observation admitted")
			}
		})
	}

	admitted, reason, err := cfg.admitObservation(context.Background(), cfg.apiSources["ScanWriter"], testObservation(), testObservation().observedAt, tagger, nil)
	requireNoError(t, err)

	if reason != reasonValid || len(admitted.subjects) != 2 {
		t.Fatalf("admitted=%d reason=%s", len(admitted.subjects), reason)
	}
}

// TestSourceSelectionNeverFallsBack separates authenticated principals from host execution provenance.
func TestSourceSelectionNeverFallsBack(t *testing.T) {
	cfg := testConfig(t)

	for _, principal := range []string{"scanwriter", "reputation", "learn_outcome"} {
		caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{Principal: principal, AuthenticationKind: "basic"})
		requireNoError(t, err)

		if cfg.sourceForCaller(caller) != nil {
			t.Fatal("unbound caller selected a source")
		}
	}

	identity, err := pluginapi.NewExecutionIdentityView("reputation", "learn_outcome", "post_action", "enqueue", pluginapi.DecisionTargetSelector{Namespace: "authn", Action: "authenticate"})
	requireNoError(t, err)

	if cfg.sourceForExecution(identity) != nil {
		t.Fatal("internal callback inherited API source")
	}
}

// TestObservationFactsRejectCallerCausality keeps source identity and evidence origin outside the request vocabulary.
func TestObservationFactsRejectCallerCausality(t *testing.T) {
	for _, name := range []string{"causality", "independent", "policy_influenced", "evidence_origin", "source", "source_policy_id"} {
		t.Run(name, func(t *testing.T) {
			value := "host_backend_outcome"
			factValue, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &value})
			requireNoError(t, err)
			fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: observationPrefix + name, Category: pluginapi.DecisionFactCategoryResource, Value: factValue})
			requireNoError(t, err)
			facts := testObservationFacts(t, testObservation())
			facts = append(facts, fact)
			_, err = decodeObservationFacts(facts)
			requireError(t, err)
		})
	}

	_, err := decodeObservationFacts(testObservationFacts(t, testObservation()))
	requireNoError(t, err)
}

// testObservationFacts uses immutable public records to exercise the actual provider request boundary.
func testObservationFacts(t *testing.T, input observationInput) []pluginapi.DecisionFactView {
	t.Helper()

	records := make([]pluginapi.DecisionRecord, 0, len(input.subjects))
	for _, subject := range input.subjects {
		record, err := recordInputs([]outputInput{
			{name: "role", input: pluginapi.DecisionValueInput{String: &subject.role}},
			{name: "kind", input: pluginapi.DecisionValueInput{String: &subject.kind}},
			{name: "value", input: pluginapi.DecisionValueInput{String: &subject.value}},
		})
		requireNoError(t, err)

		records = append(records, record)
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	requireNoError(t, err)

	inputs := []outputInput{
		{name: "event_id", input: pluginapi.DecisionValueInput{String: &input.eventID}},
		{name: "observed_at", input: pluginapi.DecisionValueInput{Timestamp: &input.observedAt}},
		{name: "signal", input: pluginapi.DecisionValueInput{String: &input.signal}},
		{name: "subjects", input: pluginapi.DecisionValueInput{Records: &list}},
	}
	outputs, err := factOutputs(inputs)
	requireNoError(t, err)

	facts := make([]pluginapi.DecisionFactView, 0, len(inputs))

	for _, output := range outputs.Facts {
		fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: observationPrefix + output.Name, Category: pluginapi.DecisionFactCategoryResource, Value: output.Value})
		requireNoError(t, err)

		facts = append(facts, fact)
	}

	return facts
}

// TestObservationProviderRequiresReadyStorage prevents eligibility without a reliable immutable-manifest probe.
func TestObservationProviderRequiresReadyStorage(t *testing.T) {
	plugin := NewPlugin()
	plugin.config = testConfig(t)
	plugin.tagger = testTagger(t)
	input := testObservation()
	input.observedAt = time.Now().UTC()
	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{Principal: "ScanWriter", AuthenticationKind: "basic"})
	requireNoError(t, err)
	request, err := pluginapi.NewDecisionFactRequest(observeTarget, caller, testObservationFacts(t, input))
	requireNoError(t, err)

	provider := observationProvider{plugin: plugin}
	requireNoError(t, pluginapi.ValidateDecisionFactProviderDescriptor(provider.Descriptor()))
	result, err := provider.Collect(context.Background(), request)
	requireNoError(t, err)
	requireNoError(t, pluginapi.ValidateDecisionFactResult(provider.Descriptor(), result))

	if result.ErrorClass != pluginapi.DecisionErrorClassUnavailable || len(result.Facts) != 0 {
		t.Fatal("unready manifest dependency produced learning eligibility")
	}
}

type exactASNFixture struct{ binding, ip string }

// lookupASN rejects accidental address or provider substitution at the trusted enrichment seam.
func (f exactASNFixture) lookupASN(_ context.Context, binding, ip string) (string, error) {
	if binding != f.binding || ip != f.ip {
		return "", errASNUnavailable
	}

	return "64500", nil
}

// TestObservationASNExpansionRequiresExactProviderAndAdmittedIP prevents caller-supplied ASN substitution.
func TestObservationASNExpansionRequiresExactProviderAndAdmittedIP(t *testing.T) {
	cfg := testASNObservationConfig(t)

	input := testObservation()
	for _, resolver := range []asnResolver{nil, exactASNFixture{binding: "reputation/plugin.geoip.other", ip: "192.0.2.3"}, exactASNFixture{binding: "reputation/plugin.geoip.observation", ip: "192.0.2.4"}} {
		_, _, err := cfg.admitObservation(context.Background(), cfg.apiSources["ScanWriter"], input, input.observedAt, testTagger(t), resolver)
		requireError(t, err)
	}

	admitted, reason, err := cfg.admitObservation(context.Background(), cfg.apiSources["ScanWriter"], input, input.observedAt, testTagger(t), exactASNFixture{binding: "reputation/plugin.geoip.observation", ip: "192.0.2.3"})
	requireNoError(t, err)

	if reason != reasonValid || len(admitted.subjects) != 3 {
		t.Fatal("exact ASN expansion failed")
	}
}

// TestObservationRejectsCanonicalDuplicatesAcrossRoles prevents order-dependent weighting of one identity.
func TestObservationRejectsCanonicalDuplicatesAcrossRoles(t *testing.T) {
	cfg := testConfig(t)
	source := cfg.apiSources["ScanWriter"]
	source.config.AllowedSubjects["alternate"] = []string{"ip"}
	cfg.signals["scan.clean"].config.SubjectRoles["alternate"] = map[string]float64{"ip": 0.2}
	input := testObservation()
	input.subjects = append(input.subjects, subjectInput{role: "alternate", kind: "ip", value: "::ffff:192.0.2.3"})
	_, reason, err := cfg.admitObservation(context.Background(), source, input, input.observedAt, testTagger(t), nil)
	requireNoError(t, err)

	if reason != reasonDuplicate {
		t.Fatal("role alias counted the same canonical identity twice")
	}
}

// testASNObservationConfig enables exact provider-derived ASN evidence in the canonical fixture.
func testASNObservationConfig(t *testing.T) *configuration {
	t.Helper()
	raw := testGeoIPReputationConfig(t)
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)

	return cfg
}
