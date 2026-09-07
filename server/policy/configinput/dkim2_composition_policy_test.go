package configinput

import (
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"slices"
	"testing"
)

// TestDKIM2CompositionPolicyDeclaresAllOperatorScenariosAndExactProviders anchors the executable hard-cut contract.
func TestDKIM2CompositionPolicyDeclaresAllOperatorScenariosAndExactProviders(t *testing.T) {
	document := decodeDKIM2Reference(t)
	ns := document.Policy.Namespaces["dkim2"]
	want := []string{"deny_bad_reputation_body_change", "deny_bad_smtp_peer_ip_reputation", "deny_bad_smtp_peer_network_reputation", "deny_rspamd_risk_on_known_bad_ingress", "deny_body_change_for_header_only_signer", "deny_bad_smtp_peer_asn_reputation", "permit_selected_provider_header_relay"}

	names := []string{}
	for _, rule := range ns.PolicySets["verifier"].Rules {
		names = append(names, rule.Name)
	}

	for _, name := range want {
		if !slices.Contains(names, name) {
			t.Errorf("missing operator scenario %s", name)
		}
	}

	if _, present := ns.Providers["intelligence_assessment"]; !present {
		t.Fatal("composition provider missing")
	}
}

// TestDKIM2CompositionSchemaRejectsEmptyChain prevents vacuous all-record permit predicates at admission.
func TestDKIM2CompositionSchemaRejectsEmptyChain(t *testing.T) {
	compiled := compileDKIM2ReferenceTarget(t, normalizeDKIM2Reference(t))

	records, err := decision.NewRecordList(nil)
	if err != nil {
		t.Fatal(err)
	}

	value, err := decision.NewValue(decision.ValueInput{Records: &records})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = compiled.Schema().NormalizeValue("plugin.dkim2_intelligence.assessed_chain", value); err == nil {
		t.Fatal("empty chain can reach all-record permit")
	}
}
