package service

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

type dkim2PolicyCase struct {
	name, wantRule string
	hops           []map[string]any
	peer           map[string]any
	facts          map[string]any
	complete       *bool
	providerError  bool
	permit         bool
}

// TestDKIM2CorrelatedPolicyScenarios evaluates the real compiled scheduler and canonical ordered Policy with deterministic provider facts.
func TestDKIM2CorrelatedPolicyScenarios(t *testing.T) {
	catalog, target := compileDKIM2ReferenceCatalog(t)
	compiled, _ := catalog.Lookup(target)

	for _, tc := range dkim2PolicyCases() {
		t.Run(tc.name, func(t *testing.T) {
			outputs := dkim2CompositionOutputs(t, compiled.Schema(), tc)
			assertDKIM2ReferenceProviderFacts(t, compiled.Schema(), outputs)

			provider := &countingFactProvider{facts: outputs}
			if tc.providerError {
				provider.err = errors.New("deterministic unavailable provider")
			}

			outcome := evaluateDKIM2Reference(t, catalog, target, provider, "PASS", tc.facts)

			expected := decision.EffectDeny
			if tc.permit {
				expected = decision.EffectPermit
			}

			if tc.providerError {
				expected = decision.EffectIndeterminate
			}

			if outcome.response.Effect() != expected || outcome.response.Policy().Rule() != tc.wantRule {
				t.Fatalf("got %s/%s (%s), want %s/%s", outcome.response.Effect(), outcome.response.Policy().Rule(), outcome.response.Status().Code(), expected, tc.wantRule)
			}

			if tc.providerError && !outcome.response.Status().Retryable() {
				t.Fatal("required provider outage is not retryable")
			}

			assertDKIM2DiagnosticsDoNotLeak(t, outcome.response)
		})
	}
}

// dkim2PolicyCases fixes positive, same-hop, current-target, availability and invariant precedence vectors.
func dkim2PolicyCases() []dkim2PolicyCase {
	no := false

	result := []dkim2PolicyCase{
		{name: "named current provider", permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "bad reputation and body same hop", hops: []map[string]any{{"signer_reputation_band": "suspicious", "change_classes": []string{"body.rewrite"}}}, wantRule: "deny_bad_reputation_body_change"},
		{name: "bad reputation and body split across hops", hops: []map[string]any{{"signer_reputation_band": "suspicious"}, {"change_classes": []string{"body.rewrite"}}}},
		{name: "header only signer body without header", hops: []map[string]any{{"signer_domain": "relay.example", "change_classes": []string{"body.rewrite"}}}, wantRule: "deny_body_change_for_header_only_signer"},
		{name: "header only signer header permitted", hops: []map[string]any{{"signer_domain": "relay.example", "change_classes": []string{"header.rewrite"}}}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "named provider historical only", hops: []map[string]any{{"signer_domain": "google.example"}, {"signer_domain": "other.example"}}},
		{name: "historical identity cannot be current", hops: []map[string]any{nil, {"identity_contract_state": "domain_only", "identity_contract_strength": "domain_only"}}, wantRule: "deny_target_identity"},
		{name: "named provider ASN identity distinct", hops: []map[string]any{nil, {"identity_contract_strength": "asn"}}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "current score and prior IP below direct confidence gate", peer: map[string]any{"ip_band": "suspicious", "ip_confidence": .2}, facts: map[string]any{"environment.rspamd.metric_score": 8.0}, wantRule: "deny_rspamd_risk_on_known_bad_ingress"},
		{name: "current score alone never invents bad prior state", facts: map[string]any{"environment.rspamd.metric_score": 8.0}, permit: true, wantRule: "permit_selected_provider_header_relay"},
		{name: "incomplete correlation", complete: &no, wantRule: "deny_incomplete_assessment"},
		{name: "upper case signature cannot permit", hops: []map[string]any{{"signature_state": "PASS"}}, wantRule: "deny_signature_state"},
		{name: "required provider fails", providerError: true},
		{name: "historical signer stale", hops: []map[string]any{{"signer_reputation_state": "stale"}}, wantRule: "deny_unusable_reputation"},
		{name: "current geography unavailable", peer: map[string]any{"geoip_state": "unavailable"}, wantRule: "deny_unusable_reputation"},
	}
	for _, kind := range []string{"ip", "network", "asn"} {
		result = append(result, dkim2PolicyCase{name: "independent " + kind + " risk", peer: map[string]any{kind + "_band": "suspicious", kind + "_samples": 25.0}, wantRule: "deny_bad_smtp_peer_" + kind + "_reputation"})
		for _, state := range []string{"stale", "not_found", "unavailable"} {
			result = append(result, dkim2PolicyCase{name: kind + " " + state, peer: map[string]any{kind + "_state": state}, wantRule: "deny_unusable_reputation"})
		}
	}

	for _, violation := range []string{"body_unavailable", "do_not_modify_violated", "do_not_explode_violated", "history_not_matched", "terminal_oob_required"} {
		result = append(result, dkim2PolicyCase{name: "hard " + violation, hops: []map[string]any{{"violation_classes": []string{violation}}}, wantRule: "deny_integrity_violation"})
	}

	for _, tc := range []struct{ fact, value, rule string }{{"verification_state", "FAIL", "deny_nonpass_verifier_state"}, {"authentication_state", "FAIL", "deny_nonpass_authentication"}, {"replay_class", "replayed", "deny_replay"}, {"custody_structure", "terminal_nd_requires_oob", "deny_terminal_nd"}, {"local_policy_verdict", "reject", "deny_noncontinuable_local_verdict"}, {"disposition", "reject", "deny_noncontinuable_disposition"}} {
		result = append(result, dkim2PolicyCase{name: tc.rule, facts: map[string]any{"resource.dkim2." + tc.fact: tc.value}, wantRule: tc.rule})
	}

	return result
}

// dkim2CompositionOutputs supplies deterministic composed facts without asserting real upstream storage or cryptographic work.
func dkim2CompositionOutputs(t *testing.T, schema policyruntime.CompiledSchema, tc dkim2PolicyCase) []providedFact {
	t.Helper()

	result := []providedFact{}

	for _, name := range []string{"assessed_chain", "smtp_peer"} {
		id := "plugin.dkim2_intelligence." + name
		fact, _ := schemaFactByID(schema.Facts(), id)
		recordSchema, _ := fact.RecordSchema()

		count := 1
		if name == "assessed_chain" {
			count = 2
		}

		records := make([]decision.Record, 0, count)
		for i := 0; i < count; i++ {
			values := dkim2PolicyBaseline(name, i)

			var changes map[string]any
			if name == "smtp_peer" {
				changes = tc.peer
			} else if i < len(tc.hops) {
				changes = tc.hops[i]
			}

			for key, value := range changes {
				values[key] = value
			}

			normalizeDKIM2FixtureTuples(values)
			records = append(records, dkim2PolicyRecord(t, recordSchema, values))
		}

		result = append(result, providedFact{id: id, category: decision.FactCategoryResource, value: dkim2ReferenceRecordListValue(t, records)})
	}

	complete := true
	if tc.complete != nil {
		complete = *tc.complete
	}

	return append(result, providedFact{id: "plugin.dkim2_intelligence.assessment_complete", category: decision.FactCategoryResource, value: dkim2ReferenceBooleanValue(t, complete)})
}

// dkim2PolicyBaseline returns complete safe semantic fixture values for a historical hop, target or peer.
func dkim2PolicyBaseline(name string, index int) map[string]any {
	if name == "smtp_peer" {
		values := map[string]any{"reputation_profile": "operational", "geoip_state": "fresh", "geoip_age_seconds": int64(1), "target_contract_state": "matched", "target_contract_strength": "cidr"}
		for _, kind := range []string{"ip", "network", "asn"} {
			values[kind+"_state"] = "fresh"
			values[kind+"_band"] = "neutral"
			values[kind+"_override"] = "none"
			values[kind+"_confidence"] = .9
			values[kind+"_samples"] = 25.0
			values[kind+"_risk_score"] = 0.0
			values[kind+"_trust_score"] = .2
			values[kind+"_source_diversity"] = int64(1)
			values[kind+"_age_seconds"] = int64(1)
		}

		return values
	}

	values := map[string]any{"sequence": int64(index + 1), "message_instance": int64(index + 1), "hop_binding": make([]byte, 32), "is_target": index == 1, "signer_domain": "origin.example", "signature_state": "pass", "custody_transition": "origin", "recipe_mode": "unchanged", "recipe_body_mode": "absent", "history_header_state": "matched", "history_body_state": "matched", "body_availability": "known", "signer_reputation_state": "fresh", "signer_reputation_profile": "operational", "signer_reputation_band": "neutral", "signer_override": "none", "signer_risk_score": 0.0, "signer_trust_score": .2, "signer_confidence": .9, "signer_samples": 25.0, "signer_source_diversity": int64(1), "signer_reputation_age_seconds": int64(1), "change_count": int64(0), "affected_header_count": int64(0), "identity_contract_state": "domain_only", "identity_contract_strength": "domain_only"}
	if index == 1 {
		values["signer_domain"] = "google.example"
		values["custody_transition"] = "ordinary"
		values["identity_contract_state"] = "matched"
		values["identity_contract_strength"] = "cidr"
	}

	return values
}

// dkim2PolicyRecord supplies declared fields only, preserving the host's immutable schema and privacy checks.
func dkim2PolicyRecord(t *testing.T, schema registry.RecordSchema, values map[string]any) decision.Record {
	t.Helper()

	fields := []decision.RecordField{}

	for _, field := range schema.Fields() {
		if _, exists := values[field.Name()]; !exists && !field.Required() {
			continue
		}

		value := dkim2ReferenceScalarValue(t, field.Kind())
		if input, exists := values[field.Name()]; exists {
			value = dkim2PolicyValue(t, input)
		}

		fields = append(fields, dkim2ReferenceRecordField(t, field.Name(), value))
	}

	return dkim2ReferenceRecord(t, fields)
}

// dkim2PolicyValue converts explicit test inputs without integer-to-double inference.
func dkim2PolicyValue(t *testing.T, input any) decision.Value {
	t.Helper()

	value := decision.ValueInput{}

	switch x := input.(type) {
	case string:
		value.String = &x
	case bool:
		value.Boolean = &x
	case int64:
		value.Integer = &x
	case float64:
		value.Double = &x
	case []string:
		value.Strings = x
	case []byte:
		value.Bytes = x
	default:
		t.Fatalf("unsupported Policy fixture value %T", input)
	}

	result, err := decision.NewValue(value)
	if err != nil {
		t.Fatal(err)
	}

	return result
}

// normalizeDKIM2FixtureTuples removes conditional measurements for explicit absent or failed lookup states.
func normalizeDKIM2FixtureTuples(values map[string]any) {
	for _, kind := range []string{"ip", "network", "asn"} {
		state := values[kind+"_state"]
		if state != "not_found" && state != "unavailable" {
			continue
		}

		band := "unknown"
		if state == "unavailable" {
			band = "unavailable"
		}

		values[kind+"_band"] = band
		for _, suffix := range []string{"risk_score", "trust_score", "confidence", "samples", "source_diversity", "age_seconds"} {
			delete(values, kind+"_"+suffix)
		}
	}
}
