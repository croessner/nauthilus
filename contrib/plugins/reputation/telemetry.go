package main

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const metricUnknown = "unknown"
const metricStorageSuccess = "success"

type reputationTelemetry struct {
	admission   *telemetry.Counter
	observation *telemetry.Counter
	subject     *telemetry.Counter
	storage     *telemetry.Counter
	assessment  *telemetry.Counter
	config      *configuration
}

// observedState retains diagnostics when storage is absent or loses readiness.
func (p *Plugin) observedState() (*stateOwner, *reputationTelemetry) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.state, p.telemetry
}

// metricCatalog freezes operator-compiled names and one explicit unbound sentinel.
func metricCatalog[V any](catalog map[string]V) []string {
	values := make(map[string]struct{}, len(catalog)+1)

	values[metricUnknown] = struct{}{}
	for name := range catalog {
		values[name] = struct{}{}
	}

	return slices.Sorted(maps.Keys(values))
}

// newReputationTelemetry registers only closed protocol dimensions and bounded compiled catalogs.
func newReputationTelemetry(cfg *configuration, host pluginapi.Metrics) (*reputationTelemetry, error) {
	m := &reputationTelemetry{config: cfg}
	classes := telemetry.Dimension{Name: "source_class", Values: metricCatalog(cfg.raw.SourceClassCaps)}
	signals := telemetry.Dimension{Name: "signal", Values: metricCatalog(cfg.signals)}
	kinds := telemetry.Dimension{Name: "kind", Values: []string{kindIP, kindNetwork, kindASN, kindDomain, kindAccount, kindService}}
	results := telemetry.Dimension{Name: metricResult, Values: []string{storageApplied, storageDuplicate, learningRejected, learningUnavailable, learningPartial, storageQuotaExceeded}}

	targets := map[string]struct{}{}
	for target := range cfg.bindings {
		targets[target.Namespace+"/"+target.Action] = struct{}{}
	}

	definitions := []struct {
		destination **telemetry.Counter
		name        string
		dimensions  []telemetry.Dimension
	}{
		{&m.admission, "admission_total", []telemetry.Dimension{classes, signals, {Name: "reason", Values: []string{
			reasonValid, reasonSource, reasonSignal, reasonTime, reasonMagnitude, reasonSubject, reasonDuplicate, reasonInput, reasonConflict, learningUnavailable}}}},
		{&m.observation, "observations_total", []telemetry.Dimension{classes, signals, results}},
		{&m.subject, "subject_updates_total", []telemetry.Dimension{kinds, results}},
		{&m.storage, "storage_total", []telemetry.Dimension{{Name: "script", Values: slices.Sorted(maps.Keys(reputationScripts()))},
			{Name: metricResult, Values: []string{metricStorageSuccess, learningUnavailable, reasonConflict, storageEventTime, storageModelMismatch, storageAllocationMismatch, storageQuotaExceeded, storageOverrideConflict}}}},
		{&m.assessment, "assessments_total", []telemetry.Dimension{{Name: "target", Values: metricCatalog(targets)}, kinds,
			{Name: "state", Values: []string{assessmentFresh, assessmentStale, assessmentMissing, assessmentUnavailable}},
			{Name: "band", Values: []string{bandUnknown, bandTrusted, bandPositive, bandNeutral, bandSuspicious, bandBlocked, assessmentUnavailable}},
			{Name: "override", Values: []string{overrideNone, bandTrusted, bandPositive, bandNeutral, bandSuspicious, bandBlocked}}}},
	}
	for _, definition := range definitions {
		counter, err := telemetry.RegisterCounter(host, definition.name, "Bounded reputation "+definition.name+" outcomes.", definition.dimensions...)
		if err != nil {
			return nil, err
		}

		*definition.destination = counter
	}

	return m, nil
}

// evidenceLabels excludes caller identities and replaces unregistered evidence names before emission.
func (m *reputationTelemetry) evidenceLabels(source *sourcePolicy, signal string) (string, string) {
	class := metricUnknown

	if source != nil {
		if _, exists := m.config.raw.SourceClassCaps[source.config.SourceClass]; exists {
			class = source.config.SourceClass
		}
	}

	if _, exists := m.config.signals[signal]; !exists {
		signal = metricUnknown
	}

	return class, signal
}

// recordAdmission counts non-mutating eligibility separately from actual durable application.
func (m *reputationTelemetry) recordAdmission(ctx context.Context, source *sourcePolicy, signal, reason string, err error) {
	if m == nil {
		return
	}

	class, signal := m.evidenceLabels(source, signal)

	if err != nil {
		reason = learningUnavailable
	}

	m.admission.Add(ctx, class, signal, reason)
}

// recordObservation reports one complete ingestion attempt, including duplicate and partial acknowledgement.
func (m *reputationTelemetry) recordObservation(ctx context.Context, admitted admittedObservation, result ingestionResult, err error) {
	if m == nil {
		return
	}

	class, signal := m.evidenceLabels(admitted.source, admitted.input.signal)
	m.observation.Add(ctx, class, signal, learningIngestionResult(result, err))
}

// storageMetricResult translates typed storage failures without recording raw Redis error text.
func storageMetricResult(err error) string {
	if err == nil {
		return metricStorageSuccess
	}

	for _, candidate := range []struct {
		err   error
		label string
	}{
		{errEventConflict, reasonConflict}, {errEventTime, storageEventTime}, {errModelMismatch, storageModelMismatch},
		{errAllocationMismatch, storageAllocationMismatch}, {errQuotaExceeded, storageQuotaExceeded}, {errOverrideConflict, storageOverrideConflict},
	} {
		if errors.Is(err, candidate.err) {
			return candidate.label
		}
	}

	return learningUnavailable
}
