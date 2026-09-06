//go:build reputation_integration

package main

import (
	"context"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"sync/atomic"
	"testing"
	"time"
)

type scheduledGeoIPFixture struct{ calls atomic.Int64 }

// Descriptor declares the exact upstream contract used by the independently tested real GeoIP plugin.
func (*scheduledGeoIPFixture) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{Namespace: "reputation", Name: "observation", Targets: []pluginapi.DecisionTargetSelector{observeTarget}, Timeout: time.Second,
		Inputs: []pluginapi.DecisionFactInputDescriptor{{ID: observationPrefix + fieldSubjects, Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords,
			Fields: []pluginapi.DecisionFactInputFieldDescriptor{{Name: "role", Kind: pluginapi.DecisionValueKindString}, {Name: "kind", Kind: pluginapi.DecisionValueKindString}, {Name: "value", Kind: pluginapi.DecisionValueKindString}},
		}},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{{Name: "observations", Category: pluginapi.DecisionFactCategoryEnvironment, Kind: pluginapi.DecisionValueKindRecords}},
	}
}

// Collect supplies deterministic local geography while exercising real prior-level fact propagation and storage.
func (p *scheduledGeoIPFixture) Collect(_ context.Context, request pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	p.calls.Add(1)

	records := make([]pluginapi.DecisionRecord, 0)

	for _, fact := range request.Facts() {
		if fact.ID() != observationPrefix+fieldSubjects {
			continue
		}

		list, ok := fact.Value().Records()
		if !ok {
			return pluginapi.DecisionFactResult{}, errObservationInput
		}

		subjects, err := decodeSubjectRecords(list)
		if err != nil {
			return pluginapi.DecisionFactResult{}, err
		}

		for _, subject := range subjects {
			if subject.kind != kindIP {
				continue
			}

			record, err := testGeoIPProviderRecord(subject)
			if err != nil {
				return pluginapi.DecisionFactResult{}, err
			}

			records = append(records, record)
		}
	}

	list, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	return factOutputs([]outputInput{{name: "observations", input: pluginapi.DecisionValueInput{Records: &list}}})
}

// testGeoIPProviderRecord correlates the fixture result to its actual admitted source address.
func testGeoIPProviderRecord(subject subjectInput) (pluginapi.DecisionRecord, error) {
	age, asn := int64(1), int64(64500)

	return recordInputs([]outputInput{stringOutput("ip", subject.value), stringOutput("role", subject.role), stringOutput("lookup_state", assessmentFresh),
		{name: "asn", input: pluginapi.DecisionValueInput{Integer: &asn}}, {name: "data_age_seconds", input: pluginapi.DecisionValueInput{Integer: &age}},
	})
}

// TestReputationGeoIPDependencyPropagatesExactProviderFacts covers the real scheduler, unary adapters, admission, and primary Redis state.
func TestReputationGeoIPDependencyPropagatesExactProviderFacts(t *testing.T) {
	upstream := &scheduledGeoIPFixture{}
	service, plugin := newReputationTransportExampleService(t, testGeoIPExample(t), upstream)
	engine, grpcHandler := reputationTransportHandlers(service)
	now := time.Now().UTC()
	assertObservationHTTP(t, engine, now, "")
	assertObservationGRPC(t, grpcHandler, now, "")

	if upstream.calls.Load() != 2 {
		t.Fatal("upstream dependency did not execute exactly once per request")
	}

	result := plugin.state.assess(t.Context(), subjectInput{kind: kindASN, value: "64500"}, profileOperational)
	if result.State != assessmentFresh || result.Details == nil || result.Details.Trust <= 0 {
		t.Fatal("correlated provider ASN did not receive independent evidence")
	}
}

// TestReputationGeoIPDependencyRejectsInvalidActivation rejects hidden inputs, mismatched field kinds, and missing upstream scheduling before requests.
func TestReputationGeoIPDependencyRejectsInvalidActivation(t *testing.T) {
	for _, change := range []string{"missing_dependency", "hidden_input", "wrong_kind"} {
		t.Run(change, func(t *testing.T) {
			raw := testGeoIPExample(t)

			namespace := raw["policy"].(map[string]any)["namespaces"].(map[string]any)["reputation"].(map[string]any)
			if change == "missing_dependency" {
				delete(namespace["providers"].(map[string]any)["observation_context"].(map[string]any), "requires")
			} else {
				facts := namespace["schema_contributions"].(map[string]any)["static"].(map[string]any)["observe"].(map[string]any)["versions"].(map[string]any)["v1"].(map[string]any)["facts"].([]any)
				for _, item := range facts {
					fact := item.(map[string]any)
					if fact["attribute"] != "plugin.geoip.observations" {
						continue
					}

					for _, item := range fact["record_schema"].(map[string]any)["fields"].([]any) {
						field := item.(map[string]any)
						if field["name"] != "asn" {
							continue
						}

						if change == "wrong_kind" {
							field["type"] = "boolean"
						} else {
							field["provider_visibility"] = []any{"reputation/plugin.reputation.storage"}
						}
					}
				}
			}

			bindings := transportNativeBindings(t, NewPlugin(), raw, &scheduledGeoIPFixture{})
			_, preparation, catalog := transportPreparedCatalog(t, raw, bindings)
			requireError(t, preparation.Bindings.ValidateCatalog(catalog))
		})
	}
}
