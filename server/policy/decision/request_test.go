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

package decision_test

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestDecisionRequestContainsExactlyOneInvocation(t *testing.T) {
	request := mustDecisionRequest(t)

	if request.Target().String() != "dkim2/sign-message-instance" {
		t.Fatalf("DecisionRequest.Target() = %q", request.Target().String())
	}

	assertNoExportedFieldMatching(t, reflect.TypeOf(decision.DecisionRequestInput{}), []string{"batch", "invocations"})
	assertNoExportedSliceOf(t, reflect.TypeOf(decision.DecisionRequestInput{}), reflect.TypeOf(decision.Target{}))

	serviceType := reflect.TypeOf((*decision.Service)(nil)).Elem()

	evaluate, ok := serviceType.MethodByName("Evaluate")
	if !ok {
		t.Fatal("decision.Service has no Evaluate method")
	}

	requestType := reflect.TypeOf(decision.DecisionRequest{})
	requestArguments := 0

	for index := range evaluate.Type.NumIn() {
		if evaluate.Type.In(index) == requestType {
			requestArguments++
		}
	}

	if requestArguments != 1 {
		t.Fatalf("Service.Evaluate has %d DecisionRequest arguments, want exactly 1", requestArguments)
	}

	if serviceType.NumMethod() != 1 {
		t.Fatalf("decision.Service has %d methods, want only unary Evaluate", serviceType.NumMethod())
	}
}

func TestDecisionRequestInputCannotSetTrustedCallerState(t *testing.T) {
	forbidden := []string{
		"caller",
		"principal",
		"clientid",
		"issuer",
		"scope",
		"authenticationkind",
		"sourceip",
		"mtlsidentity",
		"transportkind",
		"listener",
		"httproute",
		"grpcmethod",
		"internal",
	}

	assertNoExportedFieldMatching(t, reflect.TypeOf(decision.DecisionRequestInput{}), forbidden)

	request := mustDecisionRequest(t)
	if request.Caller().Principal() != "dkim2d@mx01" {
		t.Fatalf("DecisionRequest.Caller().Principal() = %q", request.Caller().Principal())
	}
}

func TestDecisionRequestDeeplyOwnsNestedMaps(t *testing.T) {
	value := mustStringValue(t, "example.org")
	attributes := map[string]decision.Value{"input.from_domain": value}
	request := mustDecisionRequestWithAttributes(t, attributes)

	delete(attributes, "input.from_domain")

	copyOne := request.Attributes().Values()
	delete(copyOne, "input.from_domain")

	if _, ok := request.Attributes().Get("input.from_domain"); !ok {
		t.Fatal("DecisionRequest did not retain an owned attribute value")
	}
}

func TestCallerContextDeeplyOwnsScopes(t *testing.T) {
	scopes := []string{"nauthilus:policy"}

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal:          "service-a",
		Scopes:             scopes,
		AuthenticationKind: "bearer",
		TransportKind:      "http",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	scopes[0] = "changed"
	returned := caller.Scopes()
	returned[0] = "mutated"

	if caller.Scopes()[0] != "nauthilus:policy" {
		t.Fatal("CallerContext exposed mutable scope storage")
	}
}

func TestEntityAndEnvironmentDeeplyOwnAttributes(t *testing.T) {
	value := mustStringValue(t, "example.org")
	entityInput := map[string]decision.Value{"subject.domain": value}
	environmentInput := map[string]decision.Value{"environment.domain": value}

	entity, err := decision.NewEntity(decision.EntityInput{Attributes: entityInput})
	if err != nil {
		t.Fatalf("NewEntity() error = %v", err)
	}

	environment, err := decision.NewEnvironment(decision.EnvironmentInput{Attributes: environmentInput})
	if err != nil {
		t.Fatalf("NewEnvironment() error = %v", err)
	}

	delete(entityInput, "subject.domain")
	delete(environmentInput, "environment.domain")
	delete(entity.Attributes().Values(), "subject.domain")
	delete(environment.Attributes().Values(), "environment.domain")

	if _, ok := entity.Attributes().Get("subject.domain"); !ok {
		t.Fatal("Entity exposed mutable attribute storage")
	}

	if _, ok := environment.Attributes().Get("environment.domain"); !ok {
		t.Fatal("Environment exposed mutable attribute storage")
	}
}

func TestCorrelationIDsRejectAuthorityCacheAndMetricUse(t *testing.T) {
	requestID, err := decision.NewRequestID("request-01")
	if err != nil {
		t.Fatalf("NewRequestID() error = %v", err)
	}

	decisionID, err := decision.NewDecisionID("decision-01")
	if err != nil {
		t.Fatalf("NewDecisionID() error = %v", err)
	}

	for _, use := range []decision.CorrelationUse{
		decision.CorrelationUseAuthorization,
		decision.CorrelationUseCache,
		decision.CorrelationUseMetricLabel,
	} {
		if err := requestID.ValidateUse(use); !errors.Is(err, decision.ErrCorrelationOnly) {
			t.Fatalf("RequestID.ValidateUse(%q) error = %v, want ErrCorrelationOnly", use, err)
		}

		if err := decisionID.ValidateUse(use); !errors.Is(err, decision.ErrCorrelationOnly) {
			t.Fatalf("DecisionID.ValidateUse(%q) error = %v, want ErrCorrelationOnly", use, err)
		}
	}

	for _, use := range []decision.CorrelationUse{
		decision.CorrelationUseLog,
		decision.CorrelationUseAudit,
		decision.CorrelationUseTrace,
	} {
		if err := requestID.ValidateUse(use); err != nil {
			t.Fatalf("RequestID.ValidateUse(%q) error = %v", use, err)
		}
	}

	if decision.RequestIDAttributeName != "nauthilus.policy.request_id" {
		t.Fatalf("RequestIDAttributeName = %q", decision.RequestIDAttributeName)
	}

	if decision.DecisionIDAttributeName != "nauthilus.policy.decision_id" {
		t.Fatalf("DecisionIDAttributeName = %q", decision.DecisionIDAttributeName)
	}
}

func TestDecisionContractsExcludeRetryOutcomeCacheAndReplaySurfaces(t *testing.T) {
	forbidden := []string{
		"batch",
		"cache",
		"outcome",
		"retry",
		"replay",
		"idempotency",
		"deduplication",
		"retrysafety",
		"idempotencyparameter",
		"idempotencykey",
		"retrytoken",
		"deduplicationkey",
	}

	for _, contractType := range []reflect.Type{
		reflect.TypeOf(decision.DecisionRequestInput{}),
		reflect.TypeOf(decision.DecisionResponseInput{}),
		reflect.TypeOf(decision.EvaluationOptions{}),
		reflect.TypeOf(decision.EffectRequestInput{}),
	} {
		assertNoExportedFieldMatching(t, contractType, forbidden)
	}
}

// mustDecisionRequest constructs a valid unary request for contract tests.
func mustDecisionRequest(t *testing.T) decision.DecisionRequest {
	t.Helper()

	return mustDecisionRequestWithAttributes(t, nil)
}

// mustDecisionRequestWithAttributes constructs a valid request with caller assertions.
func mustDecisionRequestWithAttributes(
	t *testing.T,
	attributes map[string]decision.Value,
) decision.DecisionRequest {
	t.Helper()

	target, err := decision.NewTarget("dkim2", "sign-message-instance")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal:          "dkim2d@mx01",
		ClientID:           "nauthilus-dkim2",
		Scopes:             []string{"nauthilus:policy"},
		AuthenticationKind: "bearer",
		SourceIP:           netip.MustParseAddr("192.0.2.10"),
		TransportKind:      "http",
		Listener:           "management",
		HTTPRoute:          "/api/v1/policy/decisions",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version:    decision.ContractVersion,
		RequestID:  "request-01",
		Target:     target,
		Attributes: attributes,
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	return request
}

// assertNoExportedFieldMatching rejects forbidden public-shaped contract fields.
func assertNoExportedFieldMatching(t *testing.T, typ reflect.Type, forbidden []string) {
	t.Helper()

	for index := range typ.NumField() {
		field := typ.Field(index)
		if !field.IsExported() {
			continue
		}

		normalized := strings.ToLower(strings.ReplaceAll(field.Name, "_", ""))
		for _, fragment := range forbidden {
			if strings.Contains(normalized, fragment) {
				t.Fatalf("%s exposes forbidden field %s", typ, field.Name)
			}
		}
	}
}

// assertNoExportedSliceOf rejects repeated invocation-shaped contract fields.
func assertNoExportedSliceOf(t *testing.T, typ reflect.Type, elementType reflect.Type) {
	t.Helper()

	for index := range typ.NumField() {
		field := typ.Field(index)
		if !field.IsExported() || field.Type.Kind() != reflect.Slice {
			continue
		}

		if field.Type.Elem() == elementType {
			t.Fatalf("%s exposes repeated %s through %s", typ, elementType, field.Name)
		}
	}
}
