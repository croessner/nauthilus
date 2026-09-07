package main

import (
	"encoding/json"
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/policy/testsupport"
	"strconv"
	"testing"
)

// TestProviderCollectsTrackedVerifierProjectionAndRejectsCorrelatedForgery exercises the actual native callback.
func TestProviderCollectsTrackedVerifierProjectionAndRejectsCorrelatedForgery(t *testing.T) {
	request := trackedRequest(t)

	source, err := projection.Decode(request)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := decodeConfig(pluginregistry.NewConfigView(testConfigMap()))
	if err != nil {
		t.Fatal(err)
	}

	plugin := &Plugin{config: cfg}
	provider := decisionProvider{plugin: plugin, config: cfg}

	for _, forged := range []bool{false, true} {
		facts := request.Facts()

		fact := testSignerAssessmentFact(t, source, cfg.raw.ReputationFact, forged)
		facts = append(facts, fact)

		enriched, err := pluginapi.NewDecisionFactRequest(request.Target(), request.Caller(), facts)
		if err != nil {
			t.Fatal(err)
		}

		result, err := provider.Collect(t.Context(), enriched)
		if err != nil {
			t.Fatal(err)
		}

		if forged {
			if result.ErrorClass == "" || len(result.Facts) != 0 {
				t.Fatal("forged hop produced partial output")
			}
		} else if result.ErrorClass != "" || len(result.Facts) != 3 {
			t.Fatalf("complete projection failed: %#v", result)
		}
	}
}

// trackedRequest decodes the shared canonical wire fixture into immutable public test inputs.
func trackedRequest(t *testing.T) pluginapi.DecisionFactRequest {
	t.Helper()

	var wire struct {
		Resource struct {
			Attributes map[string]json.RawMessage `json:"attributes"`
		} `json:"resource"`
		Environment struct {
			Attributes map[string]json.RawMessage `json:"attributes"`
		} `json:"environment"`
	}
	if err := json.Unmarshal(testsupport.TrackedDKIM2RequestBytes(t), &wire); err != nil {
		t.Fatal(err)
	}

	facts := make([]pluginapi.DecisionFactView, 0)

	for _, part := range []struct {
		category pluginapi.DecisionFactCategory
		values   map[string]json.RawMessage
	}{{pluginapi.DecisionFactCategoryResource, wire.Resource.Attributes}, {pluginapi.DecisionFactCategoryEnvironment, wire.Environment.Attributes}} {
		for name, raw := range part.values {
			fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: string(part.category) + "." + name, Category: part.category, Value: wireTestValue(t, raw)})
			if err != nil {
				t.Fatal(err)
			}

			facts = append(facts, fact)
		}
	}

	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{Principal: "rspamd", AuthenticationKind: "basic"})
	if err != nil {
		t.Fatal(err)
	}

	request, err := pluginapi.NewDecisionFactRequest(pluginapi.DecisionTargetSelector{Namespace: "dkim2", Action: "accept-message-instance"}, caller, facts)
	if err != nil {
		t.Fatal(err)
	}

	return request
}

// wireTestValue translates the published typed JSON fixture without performing semantic verification.
func wireTestValue(t *testing.T, raw json.RawMessage) pluginapi.DecisionValue {
	t.Helper()

	var wire testWireValue
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}

	input := pluginapi.DecisionValueInput{String: wire.String, Boolean: wire.Boolean, Double: wire.Double, Strings: wire.Strings, Bytes: wire.Bytes}
	if wire.Integer != nil {
		number, err := strconv.ParseInt(*wire.Integer, 10, 64)
		if err != nil {
			t.Fatal(err)
		}

		input.Integer = &number
	}

	if wire.Records != nil {
		records := make([]pluginapi.DecisionRecord, 0, len(wire.Records))
		for _, record := range wire.Records {
			fields := make([]pluginapi.DecisionRecordField, 0, len(record.Fields))
			for _, field := range record.Fields {
				value, err := pluginapi.NewDecisionRecordFieldValue(wireTestValue(t, field.Value))
				if err != nil {
					t.Fatal(err)
				}

				leaf, err := pluginapi.NewDecisionRecordField(field.Name, value)
				if err != nil {
					t.Fatal(err)
				}

				fields = append(fields, leaf)
			}

			owned, err := pluginapi.NewDecisionRecord(fields)
			if err != nil {
				t.Fatal(err)
			}

			records = append(records, owned)
		}

		list, err := pluginapi.NewDecisionRecordList(records)
		if err != nil {
			t.Fatal(err)
		}

		input.Records = &list
	}

	return testValue(t, input)
}

// testSignerAssessmentFact builds a complete typed upstream fixture from the tracked verifier bindings.
func testSignerAssessmentFact(t *testing.T, source projection.Projection, id string, forged bool) pluginapi.DecisionFactView {
	t.Helper()

	records := make([]pluginapi.DecisionRecord, 0, len(source.Chain))
	for _, hop := range source.Chain {
		records = append(records, testSignerAssessmentRecord(t, hop, forged))
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		t.Fatal(err)
	}

	fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: id, Category: pluginapi.DecisionFactCategoryResource, Value: testValue(t, pluginapi.DecisionValueInput{Records: &list})})
	if err != nil {
		t.Fatal(err)
	}

	return fact
}

// testSignerAssessmentRecord isolates the intentional binding substitution from the unchanged common tuple.
func testSignerAssessmentRecord(t *testing.T, hop projection.Hop, forged bool) pluginapi.DecisionRecord {
	t.Helper()

	fields, err := view.Encode(view.Tuple{State: view.NotFound, Profile: "operational", Band: view.Unknown, Override: view.NoOverride})
	if err != nil {
		t.Fatal(err)
	}

	b := newRecordBuilder()
	b.fields = fields
	b.text("role", "signer")
	b.text("kind", "dns_domain")
	b.text("signer_domain", hop.SignerDomain)
	b.integer("sequence", hop.Sequence)
	b.integer("message_instance", hop.MessageInstance)

	binding := hop.HopBinding
	if forged {
		binding = make([]byte, 32)
	}

	b.add("hop_binding", pluginapi.DecisionValueInput{Bytes: binding})

	raw := make([]pluginapi.DecisionRecordField, 0, len(b.fields))
	for name, value := range b.fields {
		field, err := pluginapi.NewDecisionRecordField(name, value)
		if err != nil {
			t.Fatal(err)
		}

		raw = append(raw, field)
	}

	record, err := pluginapi.NewDecisionRecord(raw)
	if err != nil {
		t.Fatal(err)
	}

	return record
}

type testWireValue struct {
	String  *string  `json:"string"`
	Boolean *bool    `json:"boolean"`
	Integer *string  `json:"integer"`
	Double  *float64 `json:"double"`
	Strings []string `json:"strings"`
	Bytes   []byte   `json:"bytes"`
	Records []struct {
		Fields []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"fields"`
	} `json:"records"`
}
