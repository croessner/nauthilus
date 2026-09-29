// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/gin-gonic/gin"
)

const internalAdmissionWaitTimeout = 10 * time.Second

// blockingAdmissionVerifier holds every admitted authentication inside its Decision Session until released.
type blockingAdmissionVerifier struct {
	entered chan struct{}
	release chan struct{}
	once    *sync.Once
}

// newBlockingAdmissionVerifier creates one verifier whose release frees all held sessions.
func newBlockingAdmissionVerifier(capacity int) blockingAdmissionVerifier {
	return blockingAdmissionVerifier{
		entered: make(chan struct{}, capacity),
		release: make(chan struct{}),
		once:    &sync.Once{},
	}
}

// releaseAll idempotently frees every held and future authentication.
func (v blockingAdmissionVerifier) releaseAll() {
	v.once.Do(func() { close(v.release) })
}

// Verify signals admission, waits for release, and then returns one successful LDAP result.
func (v blockingAdmissionVerifier) Verify(
	_ *gin.Context,
	auth *core.AuthState,
	_ []*core.PassDBMap,
) (*core.PassDBResult, error) {
	v.entered <- struct{}{}

	<-v.release

	result := core.GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = true
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendLDAP
	result.Attributes = map[string][]any{"uid": {auth.Request.Username}}

	return result, nil
}

type internalAdmissionResult struct {
	outcome *core.AuthOutcome
	err     error
}

// internalAdmissionConfig builds one LDAP-backed configuration around a top-level Policy document.
func internalAdmissionConfig(t *testing.T, policyYAML string) *config.FileSettings {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(policyYAML))
	if err != nil {
		t.Fatalf("decode internal admission policy: %v", err)
	}

	backend := &config.Backend{}
	if err = backend.Set(definitions.BackendLDAPName); err != nil {
		t.Fatalf("configure internal admission test backend: %v", err)
	}

	return &config.FileSettings{
		Policy: document.Policy,
		Server: &config.ServerSection{Backends: []*config.Backend{backend}},
	}
}

// internalAdmissionApplication builds one production application over a real coordinator and admission authority.
func internalAdmissionApplication(
	t *testing.T,
	policyYAML string,
	verifier blockingAdmissionVerifier,
) (core.AuthApplicationService, *nativeAuthGenerationRuntime) {
	t.Helper()

	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	configured := internalAdmissionConfig(t, policyYAML)
	runtime := newNativeAuthGenerationRuntime(t, configured, &pluginloader.State{})

	// Registered after the generation store cleanup, so held sessions are freed before its shutdown.
	t.Cleanup(verifier.releaseAll)

	return newNativeAuthApplicationWithVerifier(t, configured, runtime.service, verifier), runtime
}

// startInternalAdmissionAuthentication runs one backchannel authentication in the background.
func startInternalAdmissionAuthentication(
	t *testing.T,
	application core.AuthApplicationService,
	index int,
	results chan<- internalAdmissionResult,
) {
	t.Helper()

	go func() {
		requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())
		defer finalization.Complete()

		outcome, err := application.Authenticate(requestContext, core.AuthInput{
			Credentials: core.NewCredentials(
				core.WithUsername(fmt.Sprintf("admission-%d@example.test", index)),
				core.WithPassword(secret.FromBytes([]byte("internal-admission-test-password"))),
			),
			Context: core.NewAuthContext(
				core.WithProtocol(definitions.ProtoIMAP),
				core.WithClientIP("192.0.2.36"),
			),
			CorrelationID: fmt.Sprintf("internal-admission-%d", index),
			EntryPoint:    core.AuthnEntryBackchannel,
			Service:       definitions.ServGRPC,
		})

		results <- internalAdmissionResult{outcome: outcome, err: err}
	}()
}

// awaitHeldAuthentications waits until count sessions are admitted and fails on any early completion.
func awaitHeldAuthentications(
	t *testing.T,
	verifier blockingAdmissionVerifier,
	results <-chan internalAdmissionResult,
	count int,
) {
	t.Helper()

	deadline := time.After(internalAdmissionWaitTimeout)

	for admitted := 0; admitted < count; {
		select {
		case <-verifier.entered:
			admitted++
		case result := <-results:
			t.Fatalf("authentication finished before release after %d admitted sessions: %#v / %v",
				admitted, result.outcome, result.err)
		case <-deadline:
			t.Fatalf("admitted sessions = %d, want %d held concurrently", admitted, count)
		}
	}
}

// collectInternalAdmissionResults returns count finished authentication results.
func collectInternalAdmissionResults(
	t *testing.T,
	results <-chan internalAdmissionResult,
	count int,
) []internalAdmissionResult {
	t.Helper()

	collected := make([]internalAdmissionResult, 0, count)
	deadline := time.After(internalAdmissionWaitTimeout)

	for len(collected) < count {
		select {
		case result := <-results:
			collected = append(collected, result)
		case <-deadline:
			t.Fatalf("finished authentications = %d, want %d", len(collected), count)
		}
	}

	return collected
}

// internalAdmissionBoundedPolicy bounds internal authn concurrency above deliberately tight external limits.
func internalAdmissionBoundedPolicy(maxConcurrency int) string {
	return fmt.Sprintf(`policy:
  api:
    limits:
      per_client_concurrency: 1
      per_client_requests_per_second: 1
  runtime:
    authn:
      max_concurrency: %d
`, maxConcurrency)
}

// assertInternalAdmissionTempFail verifies one rejected authentication ended as a regular temporary failure.
func assertInternalAdmissionTempFail(t *testing.T, rejected internalAdmissionResult) {
	t.Helper()

	if rejected.err != nil || rejected.outcome == nil || rejected.outcome.Decision != core.AuthDecisionTempFail {
		t.Fatalf("over-capacity authentication = %#v / %v, want tempfail outcome", rejected.outcome, rejected.err)
	}

	if rejected.outcome.StatusMessage != definitions.TempFailDefault || rejected.outcome.Session == "" {
		t.Fatalf("over-capacity tempfail = %#v, want default status and session", rejected.outcome)
	}
}

// assertInternalAdmissionOK verifies that every released authentication succeeded.
func assertInternalAdmissionOK(t *testing.T, results []internalAdmissionResult) {
	t.Helper()

	for _, result := range results {
		if result.err != nil || result.outcome == nil || result.outcome.Decision != core.AuthDecisionOK {
			t.Fatalf("held authentication = %#v / %v, want OK", result.outcome, result.err)
		}
	}
}

// TestDefaultPolicyConfigDoesNotCapInternalAuthnAtExternalClientLimits proves that the external per-client
// Policy API defaults (8 concurrent, 25 per second) no longer bound internal backchannel authentication.
func TestDefaultPolicyConfigDoesNotCapInternalAuthnAtExternalClientLimits(t *testing.T) {
	const held = 32

	verifier := newBlockingAdmissionVerifier(held)
	application, _ := internalAdmissionApplication(t, "policy: {}\n", verifier)
	results := make(chan internalAdmissionResult, held)

	for index := range held {
		startInternalAdmissionAuthentication(t, application, index, results)
	}

	awaitHeldAuthentications(t, verifier, results, held)
	verifier.releaseAll()

	assertInternalAdmissionOK(t, collectInternalAdmissionResults(t, results, held))
}

// TestConfiguredInternalAuthnConcurrencyAnswersTempFail proves that policy.runtime.authn.max_concurrency bounds
// internal authentication independently and that its exhaustion is a regular temporary failure.
func TestConfiguredInternalAuthnConcurrencyAnswersTempFail(t *testing.T) {
	const held = 2

	verifier := newBlockingAdmissionVerifier(held + 1)
	application, _ := internalAdmissionApplication(t, internalAdmissionBoundedPolicy(held), verifier)
	results := make(chan internalAdmissionResult, held+1)

	for index := range held {
		startInternalAdmissionAuthentication(t, application, index, results)
	}

	awaitHeldAuthentications(t, verifier, results, held)
	startInternalAdmissionAuthentication(t, application, held, results)

	assertInternalAdmissionTempFail(t, collectInternalAdmissionResults(t, results, 1)[0])
	verifier.releaseAll()
	assertInternalAdmissionOK(t, collectInternalAdmissionResults(t, results, held))
}

// TestReloadedInternalAuthnBoundAppliesToTheNextGeneration proves that a reload replaces the internal
// admission profiles while sessions of the previous generation keep their own permits.
func TestReloadedInternalAuthnBoundAppliesToTheNextGeneration(t *testing.T) {
	const reloadedHeld = 3

	verifier := newBlockingAdmissionVerifier(reloadedHeld + 1)
	application, runtime := internalAdmissionApplication(t, internalAdmissionBoundedPolicy(1), verifier)
	results := make(chan internalAdmissionResult, reloadedHeld+2)

	startInternalAdmissionAuthentication(t, application, 0, results)
	awaitHeldAuthentications(t, verifier, results, 1)
	startInternalAdmissionAuthentication(t, application, 1, results)
	assertInternalAdmissionTempFail(t, collectInternalAdmissionResults(t, results, 1)[0])

	reloaded := internalAdmissionConfig(t, internalAdmissionBoundedPolicy(reloadedHeld))
	if err := runtime.coordinator.Apply(t.Context(), configfx.Snapshot{File: reloaded, Version: 2}); err != nil {
		t.Fatalf("Apply(reloaded internal authn bound) error = %v", err)
	}

	for index := 2; index < 2+reloadedHeld; index++ {
		startInternalAdmissionAuthentication(t, application, index, results)
	}

	awaitHeldAuthentications(t, verifier, results, reloadedHeld)
	startInternalAdmissionAuthentication(t, application, 2+reloadedHeld, results)
	assertInternalAdmissionTempFail(t, collectInternalAdmissionResults(t, results, 1)[0])

	verifier.releaseAll()
	assertInternalAdmissionOK(t, collectInternalAdmissionResults(t, results, 1+reloadedHeld))
}
