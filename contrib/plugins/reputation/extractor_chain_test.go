package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"testing"
)

// TestAssessmentChainExtractionKeepsEveryCorrelatedSigner separates read bounds from ingestion fanout.
func TestAssessmentChainExtractionKeepsEveryCorrelatedSigner(t *testing.T) {
	cfg := testConfig(t)
	extractor := extractorConfig{Attribute: "resource.chain", Field: "signer_domain", Role: "signer", Kind: kindDomain, CorrelationFields: []string{"sequence"}}

	for _, count := range []int{128, 161} {
		records := make([]pluginapi.DecisionRecord, 0, count)
		for index := 0; index < count; index++ {
			sequence := int64(index + 1)
			record, err := recordInputs([]outputInput{stringOutput("signer_domain", "example.test"), {name: "sequence", input: pluginapi.DecisionValueInput{Integer: &sequence}}})
			requireNoError(t, err)

			records = append(records, record)
		}

		list, err := pluginapi.NewDecisionRecordList(records)
		requireNoError(t, err)
		value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &list})
		requireNoError(t, err)

		subjects, err := cfg.extractValues(extractor, value)
		if count == 161 {
			requireError(t, err)
			continue
		}

		requireNoError(t, err)

		if len(subjects) != count {
			t.Fatal("assessment truncated signer coverage")
		}

		for index, subject := range subjects {
			sequence, ok := subject.correlation["sequence"].Value().Integer()
			if !ok || sequence != int64(index+1) {
				t.Fatal("assessment reordered signer correlation")
			}
		}
	}
}
