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
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestAdmissionEnforcesInheritedSubmittedFactLimit(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	configuration.GlobalLimits.MaxFacts = 1
	configuration.Profiles[0].Limits.MaxFacts = 0
	prepared := admissionTestPreparation(t, configuration)
	caller := admissionTestBearerCaller(t)

	one := admissionTestRequest(t, caller, admissionTestRequestInput{
		target: target,
		input: map[string]decision.Value{
			"request_id": admissionTestStringValue(t, "one"),
		},
	})

	permit := admissionTestPermit(t, prepared.Authority, caller, one)
	if permit.Facts().Len() <= configuration.GlobalLimits.MaxFacts {
		t.Fatalf("total facts = %d, want trusted facts excluded from submitted limit", permit.Facts().Len())
	}

	permit.Release()

	two := admissionTestRequest(t, caller, admissionTestRequestInput{
		target: target,
		subject: map[string]decision.Value{
			"account": admissionTestStringValue(t, "alice"),
		},
		input: map[string]decision.Value{
			"request_id": admissionTestStringValue(t, "two"),
		},
	})

	rejected, err := prepared.Authority.Admit(context.Background(), caller, two)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Admit() error = %v, want ErrLimitExceeded", err)
	}

	if rejected != nil {
		t.Fatal("over-fact request received a permit")
	}
}

func TestAdmissionEnforcesDeterministicLogicalRequestBytes(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{
		target: target,
		subject: map[string]decision.Value{
			"account": admissionTestStringValue(t, "alice"),
		},
		input: map[string]decision.Value{
			"request_id": admissionTestStringValue(t, "request-1"),
		},
	})

	logicalSize := logicalRequestSize(request)
	if logicalSize <= 1 {
		t.Fatalf("logical request size = %d, want meaningful positive size", logicalSize)
	}

	configuration := admissionTestConfiguration(t, reference)
	configuration.GlobalLimits.MaxRequestBytes = logicalSize
	configuration.Profiles[0].Limits.MaxRequestBytes = 0
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

	prepared, err := Prepare(configuration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare() exact boundary error = %v", err)
	}

	permit := admissionTestPermit(t, prepared.Authority, caller, request)
	permit.Release()

	configuration.GlobalLimits.MaxRequestBytes = logicalSize - 1

	prepared, err = Prepare(configuration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare() smaller boundary error = %v", err)
	}

	rejected, err := prepared.Authority.Admit(context.Background(), caller, request)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Admit() error = %v, want ErrLimitExceeded", err)
	}

	if rejected != nil {
		t.Fatal("oversized logical request received a permit")
	}
}

func TestLogicalRequestSizeIgnoresMapIterationOrder(t *testing.T) {
	t.Parallel()

	_, target, _ := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	caller := admissionTestBearerCaller(t)
	first := admissionTestRequest(t, caller, admissionTestRequestInput{
		target: target,
		input: map[string]decision.Value{
			"request_id": admissionTestStringValue(t, "request-1"),
			"another":    admissionTestStringValue(t, "request-2"),
		},
	})
	second := admissionTestRequest(t, caller, admissionTestRequestInput{
		target: target,
		input: map[string]decision.Value{
			"another":    admissionTestStringValue(t, "request-2"),
			"request_id": admissionTestStringValue(t, "request-1"),
		},
	})

	if firstSize, secondSize := logicalRequestSize(first), logicalRequestSize(second); firstSize != secondSize {
		t.Fatalf("logical request sizes = %d/%d, want deterministic equality", firstSize, secondSize)
	}
}

func TestAdmissionConcurrencyPermitLivesUntilIdempotentRelease(t *testing.T) {
	t.Parallel()

	_, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	configuration.GlobalLimits.MaxConcurrency = 1
	configuration.Profiles[0].Limits.MaxConcurrency = 0
	prepared := admissionTestPreparation(t, configuration)
	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})
	first := admissionTestPermit(t, prepared.Authority, caller, request)

	type admissionResult struct {
		permit interface{ Release() }
		err    error
	}

	result := make(chan admissionResult, 1)

	go func() {
		permit, err := prepared.Authority.Admit(context.Background(), caller, request)
		result <- admissionResult{permit: permit, err: err}
	}()

	select {
	case second := <-result:
		if !errors.Is(second.err, ErrLimitExceeded) || second.permit != nil {
			t.Fatalf("concurrent Admit() = %v/%v, want nonblocking limit rejection", second.permit, second.err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("concurrency admission blocked instead of rejecting")
	}

	first.Release()
	first.Release()

	third := admissionTestPermit(t, prepared.Authority, caller, request)
	third.Release()
}

func TestAdmissionRequestRateIsThreadSafeAndPerProfile(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	configuration.GlobalLimits.RequestsPerSecond = 1
	configuration.GlobalLimits.MaxConcurrency = 64
	configuration.Profiles[0].Limits.RequestsPerSecond = 0
	configuration.Profiles[0].Limits.MaxConcurrency = 0
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})

	prepared, err := Prepare(configuration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	caller := admissionTestBearerCaller(t)
	request := admissionTestRequest(t, caller, admissionTestRequestInput{target: target})
	start := make(chan struct{})
	results := make(chan error, 32)

	var workers sync.WaitGroup

	for range 32 {
		workers.Add(1)

		go func() {
			defer workers.Done()

			<-start

			permit, admitErr := prepared.Authority.Admit(context.Background(), caller, request)
			if permit != nil {
				permit.Release()
			}

			results <- admitErr
		}()
	}

	close(start)
	workers.Wait()
	close(results)

	allowed := 0
	limited := 0

	for admitErr := range results {
		switch {
		case admitErr == nil:
			allowed++
		case errors.Is(admitErr, ErrLimitExceeded):
			limited++
		default:
			t.Fatalf("Admit() error = %v, want nil or ErrLimitExceeded", admitErr)
		}
	}

	if allowed != 1 || limited != 31 {
		t.Fatalf("rate results = allowed:%d limited:%d, want 1/31", allowed, limited)
	}
}

func TestAdmissionRateStateIsIndependentAcrossProfiles(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	configuration := admissionTestConfiguration(t, reference)
	configuration.GlobalLimits.RequestsPerSecond = 100
	configuration.Profiles[0].Limits.RequestsPerSecond = 1
	second := cloneAdmissionTestConfiguration(configuration).Profiles[0]
	second.Principal = "second-policy-client"
	configuration.Profiles = append(configuration.Profiles, second)
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal, second.Principal})

	prepared, err := Prepare(configuration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	callers := []struct {
		caller  decision.CallerContext
		request decision.DecisionRequest
	}{
		{
			caller: admissionTestCaller(t, admissionTestCallerInput{
				principal: admissionTestPrincipal,
				scopes:    []string{definitions.ScopePolicyEvaluate},
			}),
		},
		{
			caller: admissionTestCaller(t, admissionTestCallerInput{
				principal: second.Principal,
				scopes:    []string{definitions.ScopePolicyEvaluate},
			}),
		},
	}

	for index := range callers {
		callers[index].request = admissionTestRequest(t, callers[index].caller, admissionTestRequestInput{target: target})
		permit := admissionTestPermit(t, prepared.Authority, callers[index].caller, callers[index].request)
		permit.Release()
	}

	for index := range callers {
		permit, admitErr := prepared.Authority.Admit(
			context.Background(),
			callers[index].caller,
			callers[index].request,
		)
		if !errors.Is(admitErr, ErrLimitExceeded) || permit != nil {
			t.Fatalf("second profile request %d = %v/%v, want independent rate limit", index, permit, admitErr)
		}
	}
}

func TestEquivalentBasicAndBearerShareProfileLimitState(t *testing.T) {
	t.Parallel()

	catalog, target, reference := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	credentials := admissionTestCredentials(t, []string{admissionTestPrincipal})
	basic := admissionTestCaller(t, admissionTestCallerInput{
		authenticationKind: policy.CallerAuthenticationKindBasic,
	})
	bearer := admissionTestCaller(t, admissionTestCallerInput{
		authenticationKind: policy.CallerAuthenticationKindBearer,
		scopes:             []string{definitions.ScopePolicyEvaluate},
	})
	basicRequest := admissionTestRequest(t, basic, admissionTestRequestInput{target: target})
	bearerRequest := admissionTestRequest(t, bearer, admissionTestRequestInput{target: target})

	concurrencyConfiguration := admissionTestConfiguration(t, reference)
	concurrencyConfiguration.GlobalLimits.MaxConcurrency = 1

	concurrencyPrepared, err := Prepare(concurrencyConfiguration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare(concurrency) error = %v", err)
	}

	basicPermit := admissionTestPermit(t, concurrencyPrepared.Authority, basic, basicRequest)

	bearerPermit, err := concurrencyPrepared.Authority.Admit(context.Background(), bearer, bearerRequest)
	if !errors.Is(err, ErrLimitExceeded) || bearerPermit != nil {
		t.Fatalf("Bearer concurrent with Basic = %v/%v, want shared profile limit", bearerPermit, err)
	}

	basicPermit.Release()

	bearerPermit = admissionTestPermit(t, concurrencyPrepared.Authority, bearer, bearerRequest)
	bearerPermit.Release()

	rateConfiguration := admissionTestConfiguration(t, reference)
	rateConfiguration.GlobalLimits.RequestsPerSecond = 1

	ratePrepared, err := Prepare(rateConfiguration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare(rate) error = %v", err)
	}

	basicPermit = admissionTestPermit(t, ratePrepared.Authority, basic, basicRequest)
	basicPermit.Release()

	bearerPermit, err = ratePrepared.Authority.Admit(context.Background(), bearer, bearerRequest)
	if !errors.Is(err, ErrLimitExceeded) || bearerPermit != nil {
		t.Fatalf("Bearer after Basic = %v/%v, want shared profile rate", bearerPermit, err)
	}
}
