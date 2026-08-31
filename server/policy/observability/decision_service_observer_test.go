// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func TestDecisionServiceObserverCorrelatesWithoutMetricOrPayloadLeaks(t *testing.T) {
	var logs bytes.Buffer

	collector := tracetest.Setup(t)
	metricRegistry := prometheus.NewRegistry()
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	observer, err := NewDecisionServiceObserver(logger, metricRegistry)
	if err != nil {
		t.Fatalf("NewDecisionServiceObserver() error = %v", err)
	}

	ctx, finish := observer.Start(context.Background(), decision.Observation{
		Transport: "http", AuthenticationKind: "bearer", Generation: 17, DiagnosticsRequested: true,
	})
	finish(mustSuccessfulObservationResult(t))

	normalLog, auditLog := decodeDecisionLogLines(t, logs.String())
	logOutput := logs.String()
	assertDecisionLogProjection(t, logOutput, normalLog, auditLog)

	spans := collector.Spans()
	if _, ok := tracetest.FindByNameAndAttributes(spans, DecisionSpanName,
		attribute.String(KeyRequestID, "request-correlation"),
		attribute.String(KeyDecisionID, "decision-correlation"),
	); !ok {
		t.Fatalf("decision span lacks stable correlation attributes: %#v", spans)
	}

	assertDecisionMetricsExcludeCorrelation(t, metricRegistry)

	if ctx == nil {
		t.Fatal("observer returned a nil context")
	}
}

func TestDecisionServiceObserverUsesBoundedFailureStatus(t *testing.T) {
	collector := tracetest.Setup(t)

	observer, err := NewDecisionServiceObserver(nil, prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("NewDecisionServiceObserver() error = %v", err)
	}

	_, finish := observer.Start(context.Background(), decision.Observation{
		Transport: "grpc",
	})
	finish(decision.ObservationResult{Class: decision.ObservationResultAdmissionFailure})

	spans := collector.Spans()

	span, ok := tracetest.FindByNameAndAttributes(spans, DecisionSpanName,
		attribute.String(keyNamespace, unadmitted),
		attribute.String(keyAction, unadmitted),
	)
	if !ok {
		t.Fatalf("failure span is missing: %#v", spans)
	}

	if span.Status().Code != codes.Error || span.Status().Description != string(decision.ObservationResultAdmissionFailure) {
		t.Fatalf("failure status = %#v", span.Status())
	}
}

func TestDecisionServiceObserverOmitsAbsentRequestCorrelation(t *testing.T) {
	var logs bytes.Buffer

	collector := tracetest.Setup(t)

	observer, err := NewDecisionServiceObserver(
		slog.New(slog.NewJSONHandler(&logs, nil)), prometheus.NewRegistry(),
	)
	if err != nil {
		t.Fatalf("NewDecisionServiceObserver() error = %v", err)
	}

	result := mustSuccessfulObservationResult(t)
	result.RequestID = decision.RequestID{}
	_, finish := observer.Start(context.Background(), decision.Observation{Transport: "http"})
	finish(result)

	if strings.Contains(logs.String(), KeyRequestID) || !strings.Contains(logs.String(), "decision-correlation") {
		t.Fatalf("omitted request correlation projection is invalid: %s", logs.String())
	}

	if _, ok := tracetest.FindByNameAndAttributes(collector.Spans(), DecisionSpanName,
		attribute.String(KeyDecisionID, "decision-correlation"),
	); !ok {
		t.Fatalf("Decision ID correlation is missing: %#v", collector.Spans())
	}
}

// mustSuccessfulObservationResult constructs typed admitted correlation for observer tests.
func mustSuccessfulObservationResult(t *testing.T) decision.ObservationResult {
	t.Helper()

	requestID, err := decision.NewRequestID("request-correlation")
	if err != nil {
		t.Fatalf("NewRequestID() error = %v", err)
	}

	decisionID, err := decision.NewDecisionID("decision-correlation")
	if err != nil {
		t.Fatalf("NewDecisionID() error = %v", err)
	}

	target, err := decision.NewTarget("mail", "evaluate")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return decision.ObservationResult{
		RequestID: requestID, DecisionID: decisionID, Target: target,
		Principal: "policy-client", PolicyID: "mail/default",
		Effect: "permit", StatusCode: "permit", Class: decision.ObservationResultCompleted,
		Admitted: true, DiagnosticsReleased: true,
	}
}

// assertDecisionLogProjection verifies normal/audit separation and protected-data absence.
func assertDecisionLogProjection(t *testing.T, combined string, normal string, audit string) {
	t.Helper()

	for _, required := range []string{
		"request-correlation", "decision-correlation", "policy-client", "bearer", "mail/default",
		`"nauthilus.policy.diagnostics_requested":true`, `"nauthilus.policy.diagnostics_released":true`,
		`"audit_class":"policy_decision"`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("structured log/audit lacks %q: %s", required, combined)
		}
	}

	for _, controlled := range []string{"policy-client", "bearer", "mail/default"} {
		if strings.Contains(normal, controlled) {
			t.Fatalf("normal log contains controlled audit value %q: %s", controlled, normal)
		}

		if !strings.Contains(audit, controlled) {
			t.Fatalf("controlled audit lacks %q: %s", controlled, audit)
		}
	}

	for _, protected := range []string{"203.0.113.77", "sensitive-signer.example", "exact-recipe-payload"} {
		if strings.Contains(combined, protected) {
			t.Fatalf("structured log/audit leaks %q: %s", protected, combined)
		}
	}
}

// decodeDecisionLogLines separates normal and controlled audit JSON records.
func decodeDecisionLogLines(t *testing.T, output string) (normal string, audit string) {
	t.Helper()

	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		fields := map[string]any{}
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("decode structured log: %v", err)
		}

		if fields["audit_class"] == "policy_decision" {
			audit = line
		} else {
			normal = line
		}
	}

	if normal == "" || audit == "" {
		t.Fatalf("expected normal and audit records: %s", output)
	}

	return normal, audit
}

// assertDecisionMetricsExcludeCorrelation rejects high-cardinality and protected metric labels.
func assertDecisionMetricsExcludeCorrelation(t *testing.T, registry *prometheus.Registry) {
	t.Helper()

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	serialized := strings.Builder{}
	for _, family := range families {
		serialized.WriteString(family.String())
	}

	for _, forbidden := range []string{"request-correlation", "decision-correlation", "203.0.113.77", "sensitive-signer.example"} {
		if strings.Contains(serialized.String(), forbidden) {
			t.Fatalf("metric labels contain forbidden value %q: %s", forbidden, serialized.String())
		}
	}
}
