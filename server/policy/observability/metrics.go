// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package observability

import (
	"context"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/policy"

	"github.com/prometheus/client_golang/prometheus"
)

// Result is the bounded result label type for policy metrics.
type Result string

const (
	// ResultSuccess is the bounded success value for policy metrics.
	ResultSuccess Result = "success"

	// ResultFailure is the bounded failure value for policy metrics.
	ResultFailure Result = "failure"

	// ResultError is the bounded error value for policy metrics.
	ResultError Result = "error"
)

// SnapshotBuildMeasurement records snapshot build instrumentation.
type SnapshotBuildMeasurement struct {
	Duration   time.Duration
	Result     Result
	Generation uint64
}

// CheckMeasurement records check execution instrumentation.
type CheckMeasurement struct {
	Duration   time.Duration
	Operation  policy.Operation
	Stage      policy.Stage
	Check      string
	CheckType  string
	Status     policy.CheckStatus
	ReasonCode string
}

// DecisionMeasurement records policy decision instrumentation.
type DecisionMeasurement struct {
	Mode           string
	PolicyName     string
	ResponseMarker string
	FSMEventMarker string
	Operation      policy.Operation
	Stage          policy.Stage
	Decision       policy.Decision
}

// ReloadFailureMeasurement records rejected snapshot reload attempts.
type ReloadFailureMeasurement struct {
	ReasonCode string
}

// StageMeasurement records policy stage evaluation instrumentation.
type StageMeasurement struct {
	Duration  time.Duration
	Mode      string
	Operation policy.Operation
	Stage     policy.Stage
}

// RequireCheckMeasurement records policy dependency applicability.
type RequireCheckMeasurement struct {
	Mode       string
	PolicyName string
	Check      string
	Result     string
	Operation  policy.Operation
	Stage      policy.Stage
}

// ObserveMeasurement records default-vs-custom comparison output.
type ObserveMeasurement struct {
	Result       Result
	MismatchType string
	Operation    policy.Operation
	Stage        policy.Stage
}

// FSMMeasurement records target FSM marker instrumentation.
type FSMMeasurement struct {
	Result         Result
	FSMEventMarker string
	Operation      policy.Operation
	Stage          policy.Stage
}

// RendererMeasurement records response rendering instrumentation.
type RendererMeasurement struct {
	Duration       time.Duration
	Surface        string
	ResponseMarker string
	Result         Result
}

// ObligationMeasurement records obligation instrumentation.
type ObligationMeasurement struct {
	Duration   time.Duration
	Obligation string
	Result     Result
}

// AdviceMeasurement records advice selection instrumentation.
type AdviceMeasurement struct {
	Advice string
	Result Result
}

// Recorder is the no-op-safe policy metrics boundary.
type Recorder interface {
	RecordSnapshotBuild(context.Context, SnapshotBuildMeasurement)
	RecordReloadFailure(context.Context, ReloadFailureMeasurement)
	RecordCheck(context.Context, CheckMeasurement)
	RecordStageEvaluation(context.Context, StageMeasurement)
	RecordDecision(context.Context, DecisionMeasurement)
	RecordRequireCheck(context.Context, RequireCheckMeasurement)
	RecordObserveComparison(context.Context, ObserveMeasurement)
	RecordFSMTransition(context.Context, FSMMeasurement)
	RecordResponseRender(context.Context, RendererMeasurement)
	RecordObligation(context.Context, ObligationMeasurement)
	RecordAdvice(context.Context, AdviceMeasurement)
}

type nopRecorder struct{}

func (nopRecorder) RecordSnapshotBuild(context.Context, SnapshotBuildMeasurement) {}
func (nopRecorder) RecordReloadFailure(context.Context, ReloadFailureMeasurement) {}
func (nopRecorder) RecordCheck(context.Context, CheckMeasurement)                 {}
func (nopRecorder) RecordStageEvaluation(context.Context, StageMeasurement)       {}
func (nopRecorder) RecordDecision(context.Context, DecisionMeasurement)           {}
func (nopRecorder) RecordRequireCheck(context.Context, RequireCheckMeasurement)   {}
func (nopRecorder) RecordObserveComparison(context.Context, ObserveMeasurement)   {}
func (nopRecorder) RecordFSMTransition(context.Context, FSMMeasurement)           {}
func (nopRecorder) RecordResponseRender(context.Context, RendererMeasurement)     {}
func (nopRecorder) RecordObligation(context.Context, ObligationMeasurement)       {}
func (nopRecorder) RecordAdvice(context.Context, AdviceMeasurement)               {}

// SafeRecorder returns a no-op recorder when recorder is nil.
func SafeRecorder(recorder Recorder) Recorder {
	if recorder == nil {
		return nopRecorder{}
	}

	return recorder
}

var (
	defaultRecorder     Recorder
	defaultRecorderOnce sync.Once
)

// DefaultRecorder returns the process-wide policy metrics recorder.
func DefaultRecorder() Recorder {
	defaultRecorderOnce.Do(func() {
		recorder, err := NewPrometheusRecorder(nil)
		if err != nil {
			defaultRecorder = nopRecorder{}

			return
		}

		defaultRecorder = recorder
	})

	return SafeRecorder(defaultRecorder)
}

// PrometheusRecorder owns policy-specific Prometheus collectors.
type PrometheusRecorder struct {
	snapshotBuildSeconds      *prometheus.HistogramVec
	snapshotBuildsTotal       *prometheus.CounterVec
	activeSnapshotGeneration  prometheus.Gauge
	reloadFailuresTotal       *prometheus.CounterVec
	checkDurationSeconds      *prometheus.HistogramVec
	checkResultsTotal         *prometheus.CounterVec
	checkTechnicalErrorsTotal *prometheus.CounterVec
	stageEvaluationSeconds    *prometheus.HistogramVec
	decisionsTotal            *prometheus.CounterVec
	requireChecksTotal        *prometheus.CounterVec
	observeComparisonsTotal   *prometheus.CounterVec
	fsmTransitionsTotal       *prometheus.CounterVec
	responseRenderSeconds     *prometheus.HistogramVec
	obligationDurationSeconds *prometheus.HistogramVec
	adviceSelectionsTotal     *prometheus.CounterVec
}

// NewPrometheusRecorder registers policy collectors against the provided registry.
func NewPrometheusRecorder(registerer prometheus.Registerer) (*PrometheusRecorder, error) {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	recorder := &PrometheusRecorder{
		snapshotBuildSeconds:      newPolicyHistogramVec("policy_snapshot_build_seconds", "Duration of policy snapshot builds.", "result"),
		snapshotBuildsTotal:       newPolicyCounterVec("policy_snapshot_builds_total", "Total number of policy snapshot build attempts.", "result"),
		activeSnapshotGeneration:  newPolicyGauge("policy_active_snapshot_generation", "Currently active policy snapshot generation."),
		reloadFailuresTotal:       newPolicyCounterVec("policy_snapshot_reload_failures_total", "Total number of policy snapshot reload failures where the active snapshot stayed unchanged.", "reason_code"),
		checkDurationSeconds:      newPolicyHistogramVec("policy_check_duration_seconds", "Duration of policy check execution.", "operation", "stage", "check", "check_type", "status"),
		checkResultsTotal:         newPolicyCounterVec("policy_check_results_total", "Total number of policy check results.", "operation", "stage", "check", "check_type", "status"),
		checkTechnicalErrorsTotal: newPolicyCounterVec("policy_check_technical_errors_total", "Total number of modeled policy check technical errors.", "operation", "stage", "check", "check_type", "reason_code"),
		stageEvaluationSeconds:    newPolicyHistogramVec("policy_stage_evaluation_seconds", "Duration of policy stage evaluation.", "mode", "operation", "stage"),
		decisionsTotal:            newPolicyCounterVec("policy_decisions_total", "Total number of policy decisions.", "mode", "operation", "stage", "decision", "policy_name", "response_marker", "fsm_event_marker"),
		requireChecksTotal:        newPolicyCounterVec("policy_require_checks_total", "Total number of policy require-check applicability results.", "mode", "operation", "stage", "policy_name", "check", "result"),
		observeComparisonsTotal:   newPolicyCounterVec("policy_observe_comparisons_total", "Total number of policy observe comparisons.", "operation", "stage", "result", "mismatch_type"),
		fsmTransitionsTotal:       newPolicyCounterVec("policy_fsm_transitions_total", "Total number of policy FSM marker applications.", "operation", "stage", "fsm_event_marker", "result"),
		responseRenderSeconds:     newPolicyHistogramVec("policy_response_render_seconds", "Duration of policy response rendering.", "surface", "response_marker", "result"),
		obligationDurationSeconds: newPolicyHistogramVec("policy_obligation_duration_seconds", "Duration of policy obligation execution.", "obligation", "result"),
		adviceSelectionsTotal:     newPolicyCounterVec("policy_advice_selections_total", "Total number of selected policy advice entries.", "advice", "result"),
	}

	if err := registerPolicyCollectors(registerer, recorder.collectors()); err != nil {
		return nil, err
	}

	return recorder, nil
}

func (r *PrometheusRecorder) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		r.snapshotBuildSeconds,
		r.snapshotBuildsTotal,
		r.activeSnapshotGeneration,
		r.reloadFailuresTotal,
		r.checkDurationSeconds,
		r.checkResultsTotal,
		r.checkTechnicalErrorsTotal,
		r.stageEvaluationSeconds,
		r.decisionsTotal,
		r.requireChecksTotal,
		r.observeComparisonsTotal,
		r.fsmTransitionsTotal,
		r.responseRenderSeconds,
		r.obligationDurationSeconds,
		r.adviceSelectionsTotal,
	}
}

func registerPolicyCollectors(registerer prometheus.Registerer, collectors []prometheus.Collector) error {
	for _, collector := range collectors {
		if err := registerer.Register(collector); err != nil {
			return err
		}
	}

	return nil
}

func newPolicyHistogramVec(name string, help string, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    name,
			Help:    help,
			Buckets: prometheus.ExponentialBuckets(0.001, 1.8, 15),
		},
		labels,
	)
}

func newPolicyCounterVec(name string, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: name,
			Help: help,
		},
		labels,
	)
}

func newPolicyGauge(name string, help string) prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
	)
}

// RecordSnapshotBuild records snapshot build metrics.
func (r *PrometheusRecorder) RecordSnapshotBuild(_ context.Context, measurement SnapshotBuildMeasurement) {
	if r == nil {
		return
	}

	result := string(measurement.Result)
	r.snapshotBuildSeconds.WithLabelValues(result).Observe(measurement.Duration.Seconds())
	r.snapshotBuildsTotal.WithLabelValues(result).Inc()
	r.activeSnapshotGeneration.Set(float64(measurement.Generation))
}

// RecordReloadFailure records rejected reload metrics.
func (r *PrometheusRecorder) RecordReloadFailure(_ context.Context, measurement ReloadFailureMeasurement) {
	if r == nil {
		return
	}

	r.reloadFailuresTotal.WithLabelValues(measurement.ReasonCode).Inc()
}

// RecordCheck records check execution metrics.
func (r *PrometheusRecorder) RecordCheck(_ context.Context, measurement CheckMeasurement) {
	if r == nil {
		return
	}

	labels := []string{
		string(measurement.Operation),
		string(measurement.Stage),
		measurement.Check,
		measurement.CheckType,
		string(measurement.Status),
	}

	r.checkDurationSeconds.WithLabelValues(labels...).Observe(measurement.Duration.Seconds())
	r.checkResultsTotal.WithLabelValues(labels...).Inc()

	if measurement.Status == policy.CheckStatusError && measurement.ReasonCode != "" {
		r.checkTechnicalErrorsTotal.WithLabelValues(
			string(measurement.Operation),
			string(measurement.Stage),
			measurement.Check,
			measurement.CheckType,
			measurement.ReasonCode,
		).Inc()
	}
}

// RecordStageEvaluation records stage evaluation metrics.
func (r *PrometheusRecorder) RecordStageEvaluation(_ context.Context, measurement StageMeasurement) {
	if r == nil {
		return
	}

	r.stageEvaluationSeconds.WithLabelValues(
		measurement.Mode,
		string(measurement.Operation),
		string(measurement.Stage),
	).Observe(measurement.Duration.Seconds())
}

// RecordDecision records policy decision metrics.
func (r *PrometheusRecorder) RecordDecision(_ context.Context, measurement DecisionMeasurement) {
	if r == nil {
		return
	}

	r.decisionsTotal.WithLabelValues(
		measurement.Mode,
		string(measurement.Operation),
		string(measurement.Stage),
		string(measurement.Decision),
		measurement.PolicyName,
		measurement.ResponseMarker,
		measurement.FSMEventMarker,
	).Inc()
}

// RecordRequireCheck records dependency applicability metrics.
func (r *PrometheusRecorder) RecordRequireCheck(_ context.Context, measurement RequireCheckMeasurement) {
	if r == nil {
		return
	}

	r.requireChecksTotal.WithLabelValues(
		measurement.Mode,
		string(measurement.Operation),
		string(measurement.Stage),
		measurement.PolicyName,
		measurement.Check,
		measurement.Result,
	).Inc()
}

// RecordObserveComparison records observe comparison metrics.
func (r *PrometheusRecorder) RecordObserveComparison(_ context.Context, measurement ObserveMeasurement) {
	if r == nil {
		return
	}

	r.observeComparisonsTotal.WithLabelValues(
		string(measurement.Operation),
		string(measurement.Stage),
		string(measurement.Result),
		measurement.MismatchType,
	).Inc()
}

// RecordFSMTransition records FSM marker metrics.
func (r *PrometheusRecorder) RecordFSMTransition(_ context.Context, measurement FSMMeasurement) {
	if r == nil {
		return
	}

	r.fsmTransitionsTotal.WithLabelValues(
		string(measurement.Operation),
		string(measurement.Stage),
		measurement.FSMEventMarker,
		string(measurement.Result),
	).Inc()
}

// RecordResponseRender records response rendering metrics.
func (r *PrometheusRecorder) RecordResponseRender(_ context.Context, measurement RendererMeasurement) {
	if r == nil {
		return
	}

	r.responseRenderSeconds.WithLabelValues(
		measurement.Surface,
		measurement.ResponseMarker,
		string(measurement.Result),
	).Observe(measurement.Duration.Seconds())
}

// RecordAdvice records advice selection metrics.
func (r *PrometheusRecorder) RecordAdvice(_ context.Context, measurement AdviceMeasurement) {
	if r == nil {
		return
	}

	r.adviceSelectionsTotal.WithLabelValues(
		measurement.Advice,
		string(measurement.Result),
	).Inc()
}

// RecordObligation records obligation execution metrics.
func (r *PrometheusRecorder) RecordObligation(_ context.Context, measurement ObligationMeasurement) {
	if r == nil {
		return
	}

	r.obligationDurationSeconds.WithLabelValues(
		measurement.Obligation,
		string(measurement.Result),
	).Observe(measurement.Duration.Seconds())
}
