// Copyright (C) 2026 Christian Roessner
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

package effectsupervisor

import (
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

const (
	maximumEffectOrdinal  = 4096
	maximumProviderLength = 128
	maximumMetadataLength = 64
	maximumDeadlineBudget = 10 * time.Minute
	minimumDeadlineBudget = time.Millisecond
)

var (
	// ErrInvalidPlan marks a plan that cannot be owned safely.
	ErrInvalidPlan = errors.New("invalid post-action plan")

	// ErrInvalidWork marks provider work with an unsupported internal representation.
	ErrInvalidWork = errors.New("invalid post-action work")
)

// Work is provider-private captured input that never crosses a public transport or extension API.
type Work any

// ObservabilityMetadata carries bounded redacted correlation context.
type ObservabilityMetadata struct {
	RuntimeGeneration uint64
	Source            string
}

// PlanInput contains constructor-only data for one bounded post-action attempt.
type PlanInput struct {
	Gate           FinalizationGate
	Work           Work
	DecisionID     string
	Target         string
	Provider       string
	Observability  ObservabilityMetadata
	DeadlineBudget time.Duration
	EffectOrdinal  uint32
}

// Plan is an immutable host-internal post-action acceptance request.
type Plan struct {
	executionDone  <-chan struct{}
	work           Work
	decisionID     decision.DecisionID
	target         decision.Target
	provider       string
	observability  ObservabilityMetadata
	deadlineBudget time.Duration
	effectOrdinal  uint32
	boundary       Boundary
}

// NewPlan validates and owns all generic plan metadata before supervisor acceptance.
func NewPlan(input PlanInput) (Plan, error) {
	decisionID, err := decision.NewDecisionID(input.DecisionID)
	if err != nil {
		return Plan{}, errors.Join(ErrInvalidPlan, err)
	}

	target, err := parseTarget(input.Target)
	if err != nil {
		return Plan{}, errors.Join(ErrInvalidPlan, err)
	}

	executionDone, boundary, err := captureFinalizationGate(input.Gate)
	if err != nil {
		return Plan{}, errors.Join(ErrInvalidPlan, err)
	}

	if err := validatePlanInput(input, executionDone, boundary); err != nil {
		return Plan{}, errors.Join(ErrInvalidPlan, err)
	}

	return Plan{
		executionDone:  executionDone,
		work:           input.Work,
		decisionID:     decisionID,
		target:         target,
		provider:       input.Provider,
		observability:  input.Observability,
		deadlineBudget: input.DeadlineBudget,
		effectOrdinal:  input.EffectOrdinal,
		boundary:       boundary,
	}, nil
}

// validatePlanInput checks bounded non-identity constructor fields.
func validatePlanInput(input PlanInput, executionDone <-chan struct{}, boundary Boundary) error {
	if input.EffectOrdinal == 0 || input.EffectOrdinal > maximumEffectOrdinal {
		return errors.New("effect ordinal is outside the bounded range")
	}

	if !validProvider(input.Provider) {
		return errors.New("provider identity is invalid")
	}

	if input.DeadlineBudget < minimumDeadlineBudget || input.DeadlineBudget > maximumDeadlineBudget {
		return errors.New("deadline budget is outside the bounded range")
	}

	if executionDone == nil || !validBoundary(boundary) {
		return errors.New("finalization gate is missing or invalid")
	}

	if nilWork(input.Work) {
		return ErrInvalidWork
	}

	if !validMetadataSource(input.Observability.Source) {
		return errors.New("observability source is invalid")
	}

	return nil
}

// captureFinalizationGate snapshots an interface-backed gate exactly once.
func captureFinalizationGate(gate FinalizationGate) (done <-chan struct{}, boundary Boundary, err error) {
	if nilWork(gate) {
		return nil, "", errors.New("finalization gate is missing or invalid")
	}

	defer func() {
		if recover() != nil {
			done = nil
			boundary = ""
			err = errors.New("finalization gate panicked during capture")
		}
	}()

	return gate.Done(), gate.Boundary(), nil
}

// DecisionID returns the correlation-only decision identity.
func (p Plan) DecisionID() string {
	return p.decisionID.String()
}

// EffectOrdinal returns the bounded attempt ordinal within one decision.
func (p Plan) EffectOrdinal() uint32 {
	return p.effectOrdinal
}

// Target returns the exact qualified policy target.
func (p Plan) Target() string {
	return p.target.String()
}

// Provider returns the resolved host provider binding identity.
func (p Plan) Provider() string {
	return p.provider
}

// DeadlineBudget returns the captured total acceptance-to-completion budget.
func (p Plan) DeadlineBudget() time.Duration {
	return p.deadlineBudget
}

// Observability returns bounded redacted plan metadata by value.
func (p Plan) Observability() ObservabilityMetadata {
	return p.observability
}

// Boundary returns the transport-specific application finalization boundary.
func (p Plan) Boundary() Boundary {
	return p.boundary
}

// valid reports whether a plan was constructed with all invariants intact.
func (p Plan) valid() bool {
	return p.decisionID.String() != "" &&
		p.target.String() != "/" &&
		p.effectOrdinal > 0 &&
		p.effectOrdinal <= maximumEffectOrdinal &&
		validProvider(p.provider) &&
		p.deadlineBudget >= minimumDeadlineBudget &&
		p.deadlineBudget <= maximumDeadlineBudget &&
		p.executionDone != nil &&
		validBoundary(p.boundary) &&
		!nilWork(p.work) &&
		validMetadataSource(p.observability.Source)
}

// parseTarget constructs an exact target from its qualified representation.
func parseTarget(input string) (decision.Target, error) {
	namespace, action, found := strings.Cut(input, "/")
	if !found || strings.Contains(action, "/") {
		return decision.Target{}, errors.New("target must be one qualified namespace/action identity")
	}

	return decision.NewTarget(namespace, action)
}

// validProvider enforces a bounded host-owned qualified binding identity.
func validProvider(input string) bool {
	if len(input) == 0 || len(input) > maximumProviderLength {
		return false
	}

	for _, current := range input {
		if current >= 'a' && current <= 'z' || current >= '0' && current <= '9' {
			continue
		}

		switch current {
		case '.', '/', '_', '-':
		default:
			return false
		}
	}

	return !strings.HasPrefix(input, "/") && !strings.HasSuffix(input, "/") && !strings.Contains(input, "//")
}

// validMetadataSource accepts one bounded low-cardinality source class.
func validMetadataSource(input string) bool {
	return len(input) > 0 && len(input) <= maximumMetadataLength && validProvider(input)
}

// nilWork rejects nil values hidden behind interface types.
func nilWork(work Work) bool {
	if work == nil {
		return true
	}

	value := reflect.ValueOf(work)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
