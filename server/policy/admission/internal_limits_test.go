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

package admission

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// internalLimitsFixture bundles one prepared authority with its internal caller and request.
type internalLimitsFixture struct {
	authority policyruntime.AdmissionAuthority
	caller    decision.CallerContext
	request   decision.DecisionRequest
}

// internalLimitsTestConfiguration converts the shared test profile into an internal profile under tight globals.
func internalLimitsTestConfiguration(t *testing.T, limits Limits) (Configuration, decision.Target) {
	t.Helper()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	configuration.GlobalLimits.MaxConcurrency = 1
	configuration.GlobalLimits.RequestsPerSecond = 1
	configuration.Profiles[0].AuthenticationKinds = []string{policy.CallerAuthenticationKindInternal}
	configuration.Profiles[0].Internal = true
	configuration.Profiles[0].Limits = limits

	return configuration, target
}

// newInternalLimitsFixture prepares one internal profile and its matching internal caller request.
func newInternalLimitsFixture(t *testing.T, limits Limits) internalLimitsFixture {
	t.Helper()

	configuration, target := internalLimitsTestConfiguration(t, limits)
	prepared := admissionTestPreparation(t, configuration)
	caller := admissionTestCaller(t, admissionTestCallerInput{
		authenticationKind: policy.CallerAuthenticationKindInternal,
		internal:           true,
	})

	return internalLimitsFixture{
		authority: prepared.Authority,
		caller:    caller,
		request:   admissionTestRequest(t, caller, admissionTestRequestInput{target: target}),
	}
}

// admitHeld acquires the requested number of permits without releasing them.
func (f internalLimitsFixture) admitHeld(t *testing.T, count int) []policyruntime.AdmissionPermit {
	t.Helper()

	permits := make([]policyruntime.AdmissionPermit, 0, count)
	for range count {
		permits = append(permits, admissionTestPermit(t, f.authority, f.caller, f.request))
	}

	return permits
}

// releaseWithin releases every permit and fails when any release blocks.
func releaseWithin(t *testing.T, permits []policyruntime.AdmissionPermit) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		defer close(done)

		for _, permit := range permits {
			permit.Release()
			permit.Release()
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("permit release blocked")
	}
}

func TestInternalProfileWithoutCapacityLimitsIsUnbounded(t *testing.T) {
	t.Parallel()

	fixture := newInternalLimitsFixture(t, Limits{})

	// The global external ceiling is 1 concurrent request and 1 request per second.
	permits := fixture.admitHeld(t, 64)

	releaseWithin(t, permits)

	permits = fixture.admitHeld(t, 64)
	releaseWithin(t, permits)
}

func TestInternalProfileCapacityMayExceedExternalGlobalLimits(t *testing.T) {
	t.Parallel()

	concurrency := newInternalLimitsFixture(t, Limits{MaxConcurrency: 3})
	permits := concurrency.admitHeld(t, 3)

	permit, err := concurrency.authority.Admit(context.Background(), concurrency.caller, concurrency.request)
	if permit != nil || !errors.Is(err, ErrConcurrencyLimitExceeded) || !errors.Is(err, ErrCapacityLimitExceeded) {
		t.Fatalf("fourth internal Admit() = %v/%v, want own concurrency bound", permit, err)
	}

	releaseWithin(t, permits)

	requestRate := newInternalLimitsFixture(t, Limits{RequestsPerSecond: 3})
	releaseWithin(t, requestRate.admitHeld(t, 3))

	permit, err = requestRate.authority.Admit(context.Background(), requestRate.caller, requestRate.request)
	if permit != nil || !errors.Is(err, ErrRateLimitExceeded) || !errors.Is(err, ErrCapacityLimitExceeded) {
		t.Fatalf("fourth internal Admit() = %v/%v, want own rate bound", permit, err)
	}
}

func TestInternalProfileKeepsInheritedRequestShapeLimits(t *testing.T) {
	t.Parallel()

	configuration, target := internalLimitsTestConfiguration(t, Limits{})
	configuration.GlobalLimits.MaxFacts = 1
	prepared := admissionTestPreparation(t, configuration)
	caller := admissionTestCaller(t, admissionTestCallerInput{
		authenticationKind: policy.CallerAuthenticationKindInternal,
		internal:           true,
	})
	request := admissionTestRequest(t, caller, admissionTestRequestInput{
		target:  target,
		subject: map[string]decision.Value{"account": admissionTestStringValue(t, "alice")},
		input:   map[string]decision.Value{"request_id": admissionTestStringValue(t, "one")},
	})

	permit, err := prepared.Authority.Admit(context.Background(), caller, request)
	if permit != nil || !errors.Is(err, ErrRequestLimitExceeded) {
		t.Fatalf("internal over-fact Admit() = %v/%v, want inherited request limit", permit, err)
	}
}

func TestInternalProfileRejectsInvalidLimits(t *testing.T) {
	t.Parallel()

	catalog, _, _ := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

	for name, limits := range map[string]Limits{
		"negative concurrency":         {MaxConcurrency: -1},
		"negative rate":                {RequestsPerSecond: -1},
		"request bytes above global":   {MaxRequestBytes: 4097},
		"submitted facts above global": {MaxFacts: 17},
	} {
		t.Run(name, func(t *testing.T) {
			configuration, _ := internalLimitsTestConfiguration(t, limits)

			if _, err := Prepare(configuration, catalog, credentials); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Prepare() error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestExternalProfileCapacityStaysBoundedByGlobalLimits(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

	for name, limits := range map[string]Limits{
		"concurrency above global": {MaxConcurrency: 2},
		"rate above global":        {RequestsPerSecond: 2},
	} {
		t.Run(name, func(t *testing.T) {
			configuration := admissionTestConfiguration(t, reference)
			configuration.GlobalLimits.MaxConcurrency = 1
			configuration.GlobalLimits.RequestsPerSecond = 1
			configuration.Profiles[0].Limits = limits

			if _, err := Prepare(configuration, catalog, credentials); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Prepare() error = %v, want broader external override rejected", err)
			}
		})
	}

	configuration := admissionTestConfiguration(t, reference)
	configuration.GlobalLimits.MaxConcurrency = 1
	prepared := admissionTestPreparation(t, configuration)
	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})
	held := admissionTestPermit(t, prepared.Authority, caller, request)

	permit, err := prepared.Authority.Admit(context.Background(), caller, request)
	if permit != nil || !errors.Is(err, ErrConcurrencyLimitExceeded) {
		t.Fatalf("second external Admit() = %v/%v, want inherited global concurrency", permit, err)
	}

	held.Release()
}

func TestCapacityRejectionReasonIsBounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err    error
		name   string
		reason string
		ok     bool
	}{
		{name: "concurrency", err: admissionError(ErrConcurrencyLimitExceeded, "x"), reason: "concurrency", ok: true},
		{name: "rate", err: admissionError(ErrRateLimitExceeded, "x"), reason: "rate", ok: true},
		{
			name: "wrapped rate", err: fmt.Errorf("session: %w", admissionError(ErrRateLimitExceeded, "x")),
			reason: "rate", ok: true,
		},
		{name: "generic capacity", err: ErrCapacityLimitExceeded, reason: "capacity", ok: true},
		{name: "request limit", err: admissionError(ErrRequestLimitExceeded, "x")},
		{name: "permission", err: admissionError(ErrPermissionDenied, "x")},
		{name: "nil"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reason, ok := CapacityRejectionReason(test.err)
			if reason != test.reason || ok != test.ok {
				t.Fatalf("CapacityRejectionReason() = %q/%v, want %q/%v", reason, ok, test.reason, test.ok)
			}
		})
	}
}
