// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy/callerauth"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/secret"
	"go.uber.org/fx"
)

type restartBaselineArtifacts struct {
	backendScript      string
	namedBackendScript string
	hookScript         string
	templateFile       string
	securityPolicy     string
	httpCA             string
	ldapCA             string
	remoteCA           string
	redisCA            string
	httpServerCert     string
	grpcServerCert     string
	pluginSignerKey    string
	pluginSignature    string
	pluginModule       string
}

type restartBaselineMutation struct {
	mutate func(*testing.T, *config.FileSettings, restartBaselineArtifacts)
	name   string
}

type restartTestLifecycle struct {
	hooks []fx.Hook
}

// Append records lifecycle hooks in production registration order.
func (l *restartTestLifecycle) Append(hook fx.Hook) {
	l.hooks = append(l.hooks, hook)
}

// stop runs OnStop hooks in Fx reverse registration order.
func (l *restartTestLifecycle) stop(ctx context.Context) error {
	var result error

	for index := len(l.hooks) - 1; index >= 0; index-- {
		if l.hooks[index].OnStop != nil {
			result = errors.Join(result, l.hooks[index].OnStop(ctx))
		}
	}

	return result
}

func TestProductionRestartBaselineRejectsEveryProcessOwnedDriftBeforeCommit(t *testing.T) {
	tests := restartBaselineMutations()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := newRestartBaselineArtifacts(t)
			baseline := restartBaselineCandidate(t, artifacts)

			validator, err := NewRestartBaseline(baseline)
			if err != nil {
				t.Fatalf("NewRestartBaseline() error = %v", err)
			}

			store := policyruntime.NewGenerationStore()

			coordinator := newRestartBaselineCoordinator(t, store, baseline, validator)
			if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: baseline, Version: 1}); err != nil {
				t.Fatalf("Apply(G1) error = %v", err)
			}

			active := store.Active()
			activeConfig := active.Config()
			activeCatalog := active.TargetCatalog()
			activeApplication := active.Application()
			activeBindings := active.Bindings()
			candidate := restartBaselineCandidate(t, artifacts)
			test.mutate(t, candidate, artifacts)

			err = coordinator.Apply(t.Context(), configfx.Snapshot{File: candidate, Version: 2})
			if !errors.Is(err, pluginruntime.ErrRestartRequired) {
				t.Fatalf("Apply(drift) error = %v, want ErrRestartRequired", err)
			}

			assertRestartBaselineRetainedGeneration(
				t, store, active, activeConfig, activeCatalog, activeApplication, activeBindings,
			)
		})
	}
}

func TestProductionRestartBaselineAllowsUnchangedAndLoggingOnlyCandidates(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	baseline := restartBaselineCandidate(t, artifacts)

	validator, err := NewRestartBaseline(baseline)
	if err != nil {
		t.Fatalf("NewRestartBaseline() error = %v", err)
	}

	unchanged := restartBaselineCandidate(t, artifacts)
	if err = validator.Validate(unchanged); err != nil {
		t.Fatalf("Validate(unchanged) error = %v", err)
	}

	loggingOnly := restartBaselineCandidate(t, artifacts)
	loggingOnly.Server.Log.JSON = true
	loggingOnly.Server.Log.AddSource = true

	loggingOnly.Observability.Log.JSON = true
	if err = validator.Validate(loggingOnly); err != nil {
		t.Fatalf("Validate(logging-only) error = %v", err)
	}

	policyOnly := restartBaselineCandidate(t, artifacts)
	policyOnly.Policy.API.Enabled = true

	policyOnly.Policy.API.HTTP.Enabled = true
	if err = validator.Validate(policyOnly); err != nil {
		t.Fatalf("Validate(policy-only) error = %v", err)
	}

	rblOnly := restartBaselineCandidate(t, artifacts)
	rblOnly.RBLs.Threshold++

	rblOnly.RBLs.Lists = []config.RBL{{Name: "reloadable", RBL: "rbl.example.test"}}
	if err = validator.Validate(rblOnly); err != nil {
		t.Fatalf("Validate(generation-owned RBL config) error = %v", err)
	}

	ignoredTimeout := restartBaselineCandidate(t, artifacts)

	ignoredTimeout.Server.Timeouts.SingleflightWork = time.Minute
	if err = validator.Validate(ignoredTimeout); err != nil {
		t.Fatalf("Validate(ignored singleflight timeout) error = %v", err)
	}

	unrelatedTemplate := filepath.Join(filepath.Dir(artifacts.templateFile), "README.txt")
	writeRestartBaselineArtifact(t, unrelatedTemplate, "not parsed by the HTTP template authority\n")

	if err = validator.Validate(restartBaselineCandidate(t, artifacts)); err != nil {
		t.Fatalf("Validate(unrelated template file) error = %v", err)
	}
}

func TestProductionRestartBaselineAcceptsSparseCandidate(t *testing.T) {
	configured := &config.FileSettings{}

	validator, err := NewRestartBaseline(configured)
	if err != nil {
		t.Fatalf("NewRestartBaseline(sparse) error = %v", err)
	}

	if err = validator.Validate(&config.FileSettings{}); err != nil {
		t.Fatalf("Validate(sparse) error = %v", err)
	}
}

func TestProductionRestartBaselineDistinguishesAbsentOptionalInputs(t *testing.T) {
	tests := []struct {
		candidate *config.FileSettings
		name      string
	}{
		{
			name: "Lua config pointer",
			candidate: &config.FileSettings{Lua: &config.LuaSection{
				Config: &config.LuaConf{},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline, err := NewRestartBaseline(&config.FileSettings{Lua: &config.LuaSection{}})
			if err != nil {
				t.Fatalf("NewRestartBaseline() error = %v", err)
			}

			err = baseline.Validate(test.candidate)
			if !errors.Is(err, pluginruntime.ErrRestartRequired) {
				t.Fatalf("Validate(optional presence drift) error = %v, want ErrRestartRequired", err)
			}
		})
	}
}

func TestProductionRestartBaselineRejectsDisabledBearerDriftBeforeCandidateFactories(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	configured := restartBaselineCandidate(t, artifacts)

	validator, err := NewRestartBaseline(configured)
	if err != nil {
		t.Fatalf("NewRestartBaseline() error = %v", err)
	}

	transportCalls := 0
	store := policyruntime.NewGenerationStore()

	coordinator, err := NewCoordinator(
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&pluginloader.State{},
		unusedTokenFactory,
		unusedThrottlerFactory,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			transportCalls++

			return callerauth.TransportCapabilities{}, nil
		},
		localization.NewMapCatalog(nil),
		mustStartupCatalog(t, configured, nil),
		validator,
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	if transportCalls != 1 {
		t.Fatalf("candidate factory calls after G1 = %d, want 1", transportCalls)
	}

	active := store.Active()
	candidate := restartBaselineCandidate(t, artifacts)
	candidate.IDP.OIDC.Issuer = "https://changed-disabled-issuer.example.test"

	err = coordinator.Apply(t.Context(), configfx.Snapshot{File: candidate, Version: 2})
	if !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("Apply(disabled Bearer drift) error = %v, want ErrRestartRequired", err)
	}

	if transportCalls != 1 {
		t.Fatalf("candidate factory calls after rejected G2 = %d, want unchanged 1", transportCalls)
	}

	if store.Active() != active {
		t.Fatal("disabled Bearer drift replaced the active generation")
	}
}

func TestProductionRestartBaselineCommitsLoggingOnlyCandidate(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	baseline := restartBaselineCandidate(t, artifacts)

	validator, err := NewRestartBaseline(baseline)
	if err != nil {
		t.Fatalf("NewRestartBaseline() error = %v", err)
	}

	store := policyruntime.NewGenerationStore()

	coordinator := newRestartBaselineCoordinator(t, store, baseline, validator)
	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: baseline, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	candidate := restartBaselineCandidate(t, artifacts)

	candidate.Server.Log.JSON = true
	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: candidate, Version: 2}); err != nil {
		t.Fatalf("Apply(logging-only G2) error = %v", err)
	}

	active := store.Active()
	if active == nil || active.ID() != 2 || active.Config() != candidate {
		t.Fatalf("active logging-only generation = %#v, want exact G2 candidate", active)
	}
}

func TestArtifactSnapshotLifecycleRejectCommitRetirementAndProcessShutdown(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	boot := restartBaselineCandidate(t, artifacts)

	validator, err := NewRestartBaseline(boot)
	if err != nil {
		t.Fatalf("NewRestartBaseline() error = %v", err)
	}

	bootSnapshot := boot.ArtifactSnapshot()
	store := policyruntime.NewGenerationStore()

	coordinator := newRestartBaselineCoordinator(t, store, boot, validator)
	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: boot, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	assertRestartRejectedCandidateReleasesArtifacts(t, coordinator, artifacts, bootSnapshot)
	assertRestartLifecycleRetiresArtifactOwners(t, coordinator, store, validator, artifacts, bootSnapshot)
}

// assertRestartRejectedCandidateReleasesArtifacts verifies pre-prepare rejection retains only boot ownership.
func assertRestartRejectedCandidateReleasesArtifacts(
	t *testing.T,
	coordinator *Coordinator,
	artifacts restartBaselineArtifacts,
	bootSnapshot *config.ArtifactSnapshot,
) {
	t.Helper()

	rejected := restartBaselineCandidate(t, artifacts)
	rejected.Server.Address = "127.0.0.1:9440"

	err := coordinator.Apply(t.Context(), configfx.Snapshot{File: rejected, Version: 2})
	if !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("Apply(restart rejection) error = %v, want ErrRestartRequired", err)
	}

	if snapshot := rejected.ArtifactSnapshot(); snapshot == nil || !snapshot.IsReleased() {
		t.Fatal("restart rejection before policy preparation retained candidate artifact bytes")
	}

	if bootSnapshot == nil || bootSnapshot.IsReleased() {
		t.Fatal("restart rejection cleared the active boot generation or process lease")
	}
}

// assertRestartLifecycleRetiresArtifactOwners verifies generation and process owners release independently.
func assertRestartLifecycleRetiresArtifactOwners(
	t *testing.T,
	coordinator *Coordinator,
	store *policyruntime.GenerationStore,
	validator RestartBaselineValidator,
	artifacts restartBaselineArtifacts,
	bootSnapshot *config.ArtifactSnapshot,
) {
	t.Helper()

	generationTwo := restartBaselineCandidate(t, artifacts)
	if err := coordinator.Apply(t.Context(), configfx.Snapshot{File: generationTwo, Version: 2}); err != nil {
		t.Fatalf("Apply(G2) error = %v", err)
	}

	generationTwoSnapshot := generationTwo.ArtifactSnapshot()
	if generationTwoSnapshot == nil || generationTwoSnapshot.IsReleased() {
		t.Fatal("committed G2 did not retain its artifact lease")
	}

	if bootSnapshot.IsReleased() {
		t.Fatal("G1 retirement cleared the boot process artifact lease")
	}

	validator.Close()

	if !bootSnapshot.IsReleased() {
		t.Fatal("explicit process shutdown did not clear the retired boot snapshot")
	}

	if generationTwoSnapshot.IsReleased() {
		t.Fatal("boot process release cleared the independently active G2 lease")
	}

	if err := store.Shutdown(t.Context()); err != nil {
		t.Fatalf("GenerationStore.Shutdown() error = %v", err)
	}

	if !generationTwoSnapshot.IsReleased() {
		t.Fatal("active generation shutdown did not clear the final G2 artifact lease")
	}
}

func TestNewRestartBaselineReleasesBootSnapshotWhenLiveArtifactsDriftAfterSeal(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	boot := restartBaselineCandidate(t, artifacts)

	snapshot, err := config.EnsureArtifactSnapshot(boot)
	if err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	writeRestartBaselineArtifact(t, artifacts.backendScript, "return 'mutated after seal'\n")

	validator, err := NewRestartBaseline(boot)
	if !errors.Is(err, config.ErrArtifactSnapshotDrift) {
		t.Fatalf("NewRestartBaseline() error = %v, want ErrArtifactSnapshotDrift", err)
	}

	if validator != nil {
		t.Fatal("NewRestartBaseline() returned a validator for a drifted boot snapshot")
	}

	if !snapshot.IsReleased() {
		t.Fatal("rejected boot snapshot retained captured artifact bytes")
	}
}

func TestRestartBaselineFxLifecycleReleasesOnlyTheProcessLeaseOnStop(t *testing.T) {
	configured := &config.FileSettings{}
	lifecycle := &restartTestLifecycle{}

	validator, err := provideRestartBaseline(
		lifecycle,
		configfx.NewProviderWithSnapshot(configured),
	)
	if err != nil {
		t.Fatalf("provideRestartBaseline() error = %v", err)
	}

	snapshot := configured.ArtifactSnapshot()

	resource, err := newArtifactSnapshotResource(snapshot)
	if err != nil {
		t.Fatalf("newArtifactSnapshotResource() error = %v", err)
	}

	if err = resource.Dispose(t.Context()); err != nil {
		t.Fatalf("Dispose(generation) error = %v", err)
	}

	if snapshot == nil || snapshot.IsReleased() {
		t.Fatal("generation retirement cleared the Fx process lease")
	}

	if err = lifecycle.stop(t.Context()); err != nil {
		t.Fatalf("lifecycle stop error = %v", err)
	}

	if !snapshot.IsReleased() {
		t.Fatal("Fx stop did not release the final process artifact lease")
	}

	validator.Close()
}

func TestArtifactSnapshotValidationDriftReleasesCandidateAndRetainsGeneration(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	boot := restartBaselineCandidate(t, artifacts)

	validator, err := NewRestartBaseline(boot)
	if err != nil {
		t.Fatalf("NewRestartBaseline() error = %v", err)
	}

	t.Cleanup(validator.Close)

	mutateDuringPreparation := false
	transport := func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
		if mutateDuringPreparation {
			writeRestartBaselineArtifact(t, artifacts.backendScript, "return 'mutated during preparation'\n")

			mutateDuringPreparation = false
		}

		return callerauth.TransportCapabilities{}, nil
	}
	store := policyruntime.NewGenerationStore()

	coordinator := newRestartBaselineCoordinatorWithTransport(t, store, boot, validator, transport)
	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: boot, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	active := store.Active()

	candidate := restartBaselineCandidate(t, artifacts)
	mutateDuringPreparation = true

	err = coordinator.Apply(t.Context(), configfx.Snapshot{File: candidate, Version: 2})
	if !errors.Is(err, config.ErrArtifactSnapshotDrift) {
		t.Fatalf("Apply(post-prepare drift) error = %v, want ErrArtifactSnapshotDrift", err)
	}

	if candidate.ArtifactSnapshot() == nil || !candidate.ArtifactSnapshot().IsReleased() {
		t.Fatal("validation-rejected candidate retained its artifact snapshot")
	}

	if store.Active() != active || boot.ArtifactSnapshot().IsReleased() {
		t.Fatal("validation rejection replaced or cleared G1")
	}
}

func TestArtifactSnapshotDiscardAndCommitCASFailureReleaseCandidate(t *testing.T) {
	artifacts := newRestartBaselineArtifacts(t)
	boot := restartBaselineCandidate(t, artifacts)

	validator, err := NewRestartBaseline(boot)
	if err != nil {
		t.Fatalf("NewRestartBaseline() error = %v", err)
	}

	t.Cleanup(validator.Close)

	store := policyruntime.NewGenerationStore()

	coordinator := newRestartBaselineCoordinator(t, store, boot, validator)
	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: boot, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	assertRestartCandidateDiscardReleasesArtifacts(t, coordinator, artifacts)
	assertRestartCASLoserReleasesArtifacts(t, coordinator, artifacts)
}

// assertRestartCandidateDiscardReleasesArtifacts verifies explicit discard releases the candidate lease.
func assertRestartCandidateDiscardReleasesArtifacts(
	t *testing.T,
	coordinator *Coordinator,
	artifacts restartBaselineArtifacts,
) {
	t.Helper()

	discarded := restartBaselineCandidate(t, artifacts)

	discardContext, discardedResource, err := claimCandidateArtifactContext(t.Context(), discarded)
	if err != nil {
		t.Fatalf("claim discarded candidate artifacts: %v", err)
	}

	discardCandidate, err := coordinator.runtime.Prepare(discardContext, policyruntime.PrepareInput{
		Config: discarded,
		ID:     2,
	})
	if err != nil {
		_ = discardedResource.Dispose(discardContext)

		t.Fatalf("Prepare(discarded) error = %v", err)
	}

	if err = coordinator.runtime.Discard(discardContext, discardCandidate); err != nil {
		t.Fatalf("Discard() error = %v", err)
	}

	if snapshot := discarded.ArtifactSnapshot(); snapshot == nil || !snapshot.IsReleased() {
		t.Fatal("explicit candidate discard retained artifact bytes")
	}
}

// assertRestartCASLoserReleasesArtifacts verifies commit contention releases the losing candidate lease.
func assertRestartCASLoserReleasesArtifacts(
	t *testing.T,
	coordinator *Coordinator,
	artifacts restartBaselineArtifacts,
) {
	t.Helper()

	loser := restartBaselineCandidate(t, artifacts)

	loserContext, loserResource, err := claimCandidateArtifactContext(t.Context(), loser)
	if err != nil {
		t.Fatalf("claim CAS-loser artifacts: %v", err)
	}

	losingCandidate, err := coordinator.runtime.Prepare(loserContext, policyruntime.PrepareInput{
		Config: loser,
		ID:     2,
	})
	if err != nil {
		_ = loserResource.Dispose(loserContext)

		t.Fatalf("Prepare(CAS loser) error = %v", err)
	}

	if err := coordinator.runtime.Validate(loserContext, losingCandidate); err != nil {
		t.Fatalf("Validate(CAS loser) error = %v", err)
	}

	winner := restartBaselineCandidate(t, artifacts)
	if err := coordinator.Apply(t.Context(), configfx.Snapshot{File: winner, Version: 3}); err != nil {
		t.Fatalf("Apply(CAS winner) error = %v", err)
	}

	if _, err := coordinator.runtime.Commit(loserContext, losingCandidate); !errors.Is(err, policyruntime.ErrGenerationChanged) {
		t.Fatalf("Commit(CAS loser) error = %v, want ErrGenerationChanged", err)
	}

	if snapshot := loser.ArtifactSnapshot(); snapshot == nil || !snapshot.IsReleased() {
		t.Fatal("commit CAS loser retained artifact bytes")
	}
}

func TestProductionCoordinatorRequiresRestartBaseline(t *testing.T) {
	configured := &config.FileSettings{}

	_, err := NewCoordinator(
		policyruntime.NewGenerationStore(),
		nil,
		&pluginloader.State{},
		unusedTokenFactory,
		unusedThrottlerFactory,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{}, nil
		},
		localization.NewMapCatalog(nil),
		mustStartupCatalog(t, configured, nil),
		nil,
	)
	if !errors.Is(err, policyruntime.ErrInvalidGeneration) {
		t.Fatalf("NewCoordinator(nil restart baseline) error = %v, want ErrInvalidGeneration", err)
	}
}

// restartBaselineMutations returns one independent drift case per process-owned class.
func restartBaselineMutations() []restartBaselineMutation {
	mutations := restartStorageAndLuaMutations()
	mutations = append(mutations, restartAuthAndRouteMutations()...)
	mutations = append(mutations, restartTransportAndProcessMutations()...)
	mutations = append(mutations, restartRemoteAndPluginMutations()...)

	return mutations
}

// restartStorageAndLuaMutations covers process-owned storage, LDAP, Lua, and HTTP client state.
func restartStorageAndLuaMutations() []restartBaselineMutation {
	return []restartBaselineMutation{
		{name: "Redis prefix", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Redis.Prefix = "changed"
		}},
		{name: "Redis secret", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Redis.EncryptionSecret = secret.New("changed-redis-encryption-secret")
		}},
		{name: "Redis TLS resource content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.redisCA, "changed Redis CA\n")
		}},
		{name: "account cache", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Redis.AccountLocalCache.MaxItems++
		}},
		{name: "Redis timeouts", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Timeouts.RedisRead++
		}},
		{name: "backend order", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Backends[0], candidate.Server.Backends[1] = candidate.Server.Backends[1], candidate.Server.Backends[0]
		}},
		{name: "LDAP workers and pools", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.LDAP.Config.LookupPoolSize++
		}},
		{name: "named LDAP pool", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.LDAP.OptionalLDAPPools["users"].LookupQueueLength++
		}},
		{name: "LDAP TLS resource content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.ldapCA, "changed LDAP CA\n")
		}},
		{name: "Lua workers queues and pools", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Lua.Config.HookVMPoolSize++
		}},
		{name: "named Lua backend", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Lua.OptionalLuaBackends["named"].QueueLength++
		}},
		{name: "Lua backend script content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.backendScript, "return 'changed backend'\n")
		}},
		{name: "named Lua backend script content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.namedBackendScript, "return 'changed named backend'\n")
		}},
		{name: "HTTP client VM inputs", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.HTTPClient.MaxConnsPerHost++
		}},
		{name: "HTTP client TLS", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.HTTPClient.TLS.SkipVerify = true
		}},
		{name: "HTTP client TLS resource content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.httpCA, "changed HTTP CA\n")
		}},
	}
}

// restartAuthAndRouteMutations covers process-owned request and route assembly state.
func restartAuthAndRouteMutations() []restartBaselineMutation {
	return []restartBaselineMutation{
		{name: "brute-force toleration", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.BruteForce.ToleratePercent++
		}},
		{name: "maximum concurrency", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.MaxConcurrentRequests++
		}},
		{name: "disabled HTTP endpoint", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.DisabledEndpoints.AuthJSON = true
		}},
		{name: "request header mapping", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.DefaultHTTPRequestHeader.Username = "X-Changed-User"
		}},
		{name: "master-user mapping", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.MasterUser.Enabled = !candidate.Server.MasterUser.Enabled
		}},
		{name: "backchannel route graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.OIDCAuth.Enabled = true
		}},
		{name: "IdP route graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.IDP.OIDC.Enabled = true
		}},
		{name: "frontend template content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.templateFile, "{{ define \"changed\" }}changed{{ end }}\n")
		}},
	}
}

// restartTransportAndProcessMutations covers listener, middleware, observability, and boot graph state.
func restartTransportAndProcessMutations() []restartBaselineMutation {
	return []restartBaselineMutation{
		{name: "HTTP listener address", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Address = "127.0.0.1:9440"
		}},
		{name: "HTTP middleware graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Middlewares.Logging = restartBaselineBool(false)
		}},
		{name: "pprof graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Insights.EnablePprof = true
		}},
		{name: "tracing graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Insights.Tracing.Enabled = true
		}},
		{name: "HTTP rate graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.RateLimitBurst++
		}},
		{name: "CORS graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.CORS.Enabled = restartBaselineBool(true)
		}},
		{name: "compression graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Compression.Enabled = true
		}},
		{name: "security.txt graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.SecurityTxt.Enabled = true
		}},
		{name: "security.txt policy content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.securityPolicy, "changed security policy\n")
		}},
		{name: "keepalive graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.KeepAlive.Enabled = true
		}},
		{name: "management OpenAPI graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.OpenAPIValidation.Enabled = true
		}},
		{name: "process identity", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.RunAsUser = "changed-user"
		}},
		{name: "HTTP listener TLS resource content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.httpServerCert, "changed HTTP listener cert\n")
		}},
		{name: "gRPC listener TLS resource content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.grpcServerCert, "changed gRPC listener cert\n")
		}},
		{name: "boot control graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Controls = nil
		}},
		{name: "boot service graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Server.Services = nil
		}},
		{name: "background monitor graph", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.BackendServerMonitoring.ConnectInterval++
		}},
	}
}

// restartRemoteAndPluginMutations covers remote authorities, hooks, and native plugin state.
func restartRemoteAndPluginMutations() []restartBaselineMutation {
	return []restartBaselineMutation{
		{name: "remote authority client", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Runtime.Clients.GRPC.NauthilusAuthorities["edge"].Address = "127.0.0.1:9445"
		}},
		{name: "remote authority TLS resource content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.remoteCA, "changed remote CA\n")
		}},
		{name: "remote backend authority", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Auth.Backends.Remote["edge"].Authority = "changed-edge"
		}},
		{name: "remote backend mode", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Auth.Backends.Remote["edge"].Mode = ""
		}},
		{name: "remote backend allowed operations", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Auth.Backends.Remote["edge"].AllowedOperations = append(
				candidate.Auth.Backends.Remote["edge"].AllowedOperations,
				config.RemoteBackendOperationListAccounts,
			)
		}},
		{name: "remote backend timeout", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Auth.Backends.Remote["edge"].Timeout++
		}},
		{name: "auth Lua hook path", mutate: func(t *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			replacement := filepath.Join(t.TempDir(), "replacement-hook.lua")
			writeRestartBaselineArtifact(t, replacement, "return 'hook'\n")
			candidate.Lua.Hooks[0].ScriptPath = replacement
		}},
		{name: "auth Lua hook content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.hookScript, "return 'changed hook'\n")
		}},
		{name: "disabled Bearer token authority", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.IDP.OIDC.Issuer = "https://changed-issuer.example.test"
		}},
		{name: "native plugin startup configuration", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Plugins.VerificationPolicy = config.PluginVerificationPolicyChecksumRequired
		}},
		{name: "plugin signer key content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.pluginSignerKey, "changed plugin signer key\n")
		}},
		{name: "plugin detached signature content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.pluginSignature, "changed plugin signature\n")
		}},
		{name: "plugin module content", mutate: func(t *testing.T, _ *config.FileSettings, artifacts restartBaselineArtifacts) {
			writeRestartBaselineArtifact(t, artifacts.pluginModule, "changed native module\n")
		}},
		{name: "plugin-visible RBL configuration", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Auth.Controls.RBL.Lists = append(candidate.Auth.Controls.RBL.Lists, config.RBL{
				Name: "plugin-visible", RBL: "rbl.example.test",
			})
		}},
		{name: "plugin-visible unknown configuration", mutate: func(_ *testing.T, candidate *config.FileSettings, _ restartBaselineArtifacts) {
			candidate.Other["plugin_visible"] = "changed"
		}},
	}
}

// newRestartBaselineArtifacts creates boot-owned Lua source files for one subtest.
func newRestartBaselineArtifacts(t *testing.T) restartBaselineArtifacts {
	t.Helper()

	directory := t.TempDir()

	templateDirectory := filepath.Join(directory, "templates")
	if err := os.MkdirAll(templateDirectory, 0o700); err != nil {
		t.Fatalf("create restart baseline template directory: %v", err)
	}

	artifacts := restartBaselineArtifacts{
		backendScript:      filepath.Join(directory, "backend.lua"),
		namedBackendScript: filepath.Join(directory, "named-backend.lua"),
		hookScript:         filepath.Join(directory, "hook.lua"),
		templateFile:       filepath.Join(templateDirectory, "base.html"),
		securityPolicy:     filepath.Join(directory, "security-policy.txt"),
		httpCA:             filepath.Join(directory, "http-ca.pem"),
		ldapCA:             filepath.Join(directory, "ldap-ca.pem"),
		remoteCA:           filepath.Join(directory, "remote-ca.pem"),
		redisCA:            filepath.Join(directory, "redis-ca.pem"),
		httpServerCert:     filepath.Join(directory, "http-server.pem"),
		grpcServerCert:     filepath.Join(directory, "grpc-server.pem"),
		pluginSignerKey:    filepath.Join(directory, "plugin-signing-key.pub"),
		pluginSignature:    filepath.Join(directory, "plugin.sig"),
		pluginModule:       filepath.Join(directory, "plugin.so"),
	}
	writeRestartBaselineArtifact(t, artifacts.backendScript, "return 'backend'\n")
	writeRestartBaselineArtifact(t, artifacts.namedBackendScript, "return 'named backend'\n")
	writeRestartBaselineArtifact(t, artifacts.hookScript, "return 'hook'\n")
	writeRestartBaselineArtifact(t, artifacts.templateFile, "{{ define \"base\" }}base{{ end }}\n")
	writeRestartBaselineArtifact(t, artifacts.securityPolicy, "security policy\n")
	writeRestartBaselineArtifact(t, artifacts.httpCA, "HTTP CA\n")
	writeRestartBaselineArtifact(t, artifacts.ldapCA, "LDAP CA\n")
	writeRestartBaselineArtifact(t, artifacts.remoteCA, "remote CA\n")
	writeRestartBaselineArtifact(t, artifacts.redisCA, "Redis CA\n")
	writeRestartBaselineArtifact(t, artifacts.httpServerCert, "HTTP listener cert\n")
	writeRestartBaselineArtifact(t, artifacts.grpcServerCert, "gRPC listener cert\n")
	writeRestartBaselineArtifact(t, artifacts.pluginSignerKey, "plugin signer key\n")
	writeRestartBaselineArtifact(t, artifacts.pluginSignature, "plugin signature\n")
	writeRestartBaselineArtifact(t, artifacts.pluginModule, "native module\n")

	return artifacts
}

// writeRestartBaselineArtifact replaces one test-owned process artifact.
func writeRestartBaselineArtifact(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write restart baseline artifact %q: %v", path, err)
	}
}

// restartBaselineCandidate returns one detached process-owned configuration carrier.
func restartBaselineCandidate(t *testing.T, artifacts restartBaselineArtifacts) *config.FileSettings {
	t.Helper()

	parts := newRestartBaselineCandidateParts(t, artifacts)

	return &config.FileSettings{
		Runtime:       restartBaselineRuntime(artifacts),
		Observability: &config.ObservabilitySection{},
		Storage:       &config.StorageSection{Redis: parts.redis},
		Plugins:       restartBaselinePlugins(artifacts),
		Auth:          restartBaselineAuth(parts),
		Identity: &config.IdentitySection{Frontend: config.IdentityFrontendSection{
			Enabled: true,
			Assets: config.IdentityFrontendAssets{
				HTMLStaticContentPath: filepath.Dir(artifacts.templateFile),
			},
		}},
		Other:  map[string]any{"plugin_visible": "baseline"},
		Server: restartBaselineServer(parts, artifacts),
		BackendServerMonitoring: &config.BackendServerMonitoring{
			BackendServers:  []*config.BackendServer{{Protocol: "imap", Host: "127.0.0.1", Port: 143}},
			ConnectInterval: time.Minute,
		},
		LDAP: restartBaselineLDAP(artifacts),
		Lua:  restartBaselineLua(artifacts),
		BruteForce: &config.BruteForceSection{
			ToleratePercent: 10, MinToleratePercent: 5, MaxToleratePercent: 25,
		},
		RBLs: &config.RBLSection{Threshold: 5},
		IDP: &config.IDPSection{OIDC: config.OIDCConfig{
			Enabled: false, Issuer: "https://issuer.example.test",
		}},
		Policy: policyconfig.PolicyConfig{},
	}
}

type restartBaselineCandidateParts struct {
	ldapBackend   *config.Backend
	luaBackend    *config.Backend
	control       *config.Control
	service       *config.Service
	masterUser    config.MasterUser
	requestHeader config.DefaultHTTPRequestHeader
	redis         config.Redis
}

// newRestartBaselineCandidateParts creates the shared selectors and storage values used by the fixture.
func newRestartBaselineCandidateParts(
	t *testing.T,
	artifacts restartBaselineArtifacts,
) restartBaselineCandidateParts {
	t.Helper()

	return restartBaselineCandidateParts{
		ldapBackend: restartBaselineBackend(t, "ldap"),
		luaBackend:  restartBaselineBackend(t, "lua"),
		control:     restartBaselineControl(t, definitions.ControlBruteForce),
		service:     restartBaselineService(t, definitions.ServiceBackendHealthChecks),
		masterUser:  config.MasterUser{Enabled: true, UserFormat: "%s*master"},
		requestHeader: config.DefaultHTTPRequestHeader{
			Username: "X-Auth-User", Password: "X-Auth-Password",
		},
		redis: config.Redis{
			Prefix: "baseline", PoolSize: 4, IdlePoolSize: 1,
			PasswordNonce: secret.New("redis-password-nonce"), EncryptionSecret: secret.New("redis-encryption-secret"),
			TLS:               config.TLS{Enabled: true, CAFile: artifacts.redisCA},
			AccountLocalCache: config.AccountLocalCache{Enabled: true, TTL: time.Minute, Shards: 4, MaxItems: 100},
		},
	}
}

// restartBaselineRuntime builds the process-owned listener and remote authority fixture.
func restartBaselineRuntime(artifacts restartBaselineArtifacts) *config.RuntimeSection {
	return &config.RuntimeSection{
		Process: config.RuntimeProcessSection{RunAsUser: "baseline-user", RunAsGroup: "baseline-group"},
		Servers: config.RuntimeServersSection{
			HTTP: config.RuntimeHTTPServerSection{Address: "127.0.0.1:8080"},
			GRPC: config.RuntimeGRPCServersSection{Authority: config.RuntimeGRPCAuthServerSection{
				Enabled: true, Address: "127.0.0.1:9443",
				TLS: config.RuntimeGRPCTLSSection{Enabled: true, Cert: artifacts.grpcServerCert},
			}},
		},
		Clients: config.RuntimeClientsSection{
			GRPC: config.RuntimeGRPCClientsSection{NauthilusAuthorities: map[string]*config.NauthilusAuthorityClientSection{
				"edge": {
					Address: "127.0.0.1:9444", Timeout: time.Second,
					TLS: config.AuthorityTLSSection{Enabled: true, CA: artifacts.remoteCA},
					CallerAuth: config.AuthorityCallerAuthSection{BasicAuth: config.BasicAuth{
						Enabled: true, Username: "edge", Password: secret.New("edge-client-password"),
					}},
				},
			}},
		},
	}
}

// restartBaselinePlugins builds the process-owned native plugin fixture.
func restartBaselinePlugins(artifacts restartBaselineArtifacts) *config.PluginsSection {
	return &config.PluginsSection{
		VerificationPolicy: config.PluginVerificationPolicyWhenPresent,
		Trust: config.PluginTrustSection{Signers: []config.PluginTrustSigner{{
			ID: "baseline", Format: config.PluginSignatureFormatSignify,
			PublicKeyFile: artifacts.pluginSignerKey,
		}}},
		Modules: []config.PluginModule{{
			Name: "baseline", Type: config.PluginModuleTypeGo, Path: artifacts.pluginModule,
			Signature: config.PluginSignatureFormatSignify + ":" + artifacts.pluginSignature,
			Signer:    "baseline",
		}},
	}
}

// restartBaselineAuth builds request, control, service, and remote backend fixture state.
func restartBaselineAuth(parts restartBaselineCandidateParts) *config.AuthSection {
	return &config.AuthSection{
		Request: config.AuthRequestSection{Headers: parts.requestHeader},
		Pipeline: config.AuthPipelineSection{
			MaxConcurrentRequests: 64, MasterUser: parts.masterUser,
		},
		Controls: config.AuthControlsSection{
			Enabled: []*config.Control{parts.control},
			RBL: &config.RBLControlSection{
				Threshold: 5, Lists: []config.RBL{{Name: "baseline", RBL: "baseline.example.test"}},
			},
		},
		Services: config.AuthServicesSection{Enabled: []*config.Service{parts.service}},
		Backends: config.AuthBackendsSection{Remote: map[string]*config.RemoteBackendSection{
			"edge": {
				Authority: "edge", Mode: config.RemoteBackendModeNauthilus,
				AllowedOperations: []string{config.RemoteBackendOperationAuth}, Timeout: time.Second,
			},
		}},
	}
}

// restartBaselineServer builds the process-owned HTTP and auth dependency fixture.
func restartBaselineServer(parts restartBaselineCandidateParts, artifacts restartBaselineArtifacts) *config.ServerSection {
	return &config.ServerSection{
		Address: "127.0.0.1:8080", MaxConcurrentRequests: 64,
		Backends: []*config.Backend{parts.ldapBackend, parts.luaBackend},
		Controls: []*config.Control{parts.control}, Services: []*config.Service{parts.service},
		Redis: parts.redis, TLS: config.TLS{Enabled: true, Cert: artifacts.httpServerCert},
		Timeouts: config.Timeouts{
			RedisRead: time.Second, RedisWrite: 2 * time.Second, LuaBackend: 3 * time.Second,
		},
		DefaultHTTPRequestHeader: parts.requestHeader,
		MasterUser:               parts.masterUser, Middlewares: config.Middlewares{Logging: restartBaselineBool(true)},
		RateLimitPerSecond: 10, RateLimitBurst: 20,
		CORS:        config.CORS{Enabled: restartBaselineBool(false)},
		SecurityTxt: config.SecurityTxt{PolicyFile: artifacts.securityPolicy},
		RunAsUser:   "baseline-user", RunAsGroup: "baseline-group",
		HTTPClient: config.HTTPClient{
			MaxConnsPerHost: 4, MaxIdleConns: 4, MaxIdleConnsPerHost: 2,
			TLS: config.HTTPClientTLS{CAFile: artifacts.httpCA},
		},
		BasicAuth: config.BasicAuth{
			Enabled: true, Username: "backchannel", Password: secret.New("backchannel-password"),
		},
		Frontend: config.Frontend{
			Enabled: true, HTMLStaticContentPath: filepath.Dir(artifacts.templateFile),
		},
	}
}

// restartBaselineLDAP builds the process-owned primary and named LDAP pools.
func restartBaselineLDAP(artifacts restartBaselineArtifacts) *config.LDAPSection {
	return &config.LDAPSection{
		Config: &config.LDAPConf{
			NumberOfWorkers: 2, LookupPoolSize: 2, AuthPoolSize: 2,
			LookupQueueLength: 8, AuthQueueLength: 8, ServerURIs: []string{"ldap://127.0.0.1:389"},
			TLSCAFile: artifacts.ldapCA,
		},
		OptionalLDAPPools: map[string]*config.LDAPConf{
			"users": {
				NumberOfWorkers: 1, LookupPoolSize: 1, AuthPoolSize: 1,
				LookupQueueLength: 4, AuthQueueLength: 4, ServerURIs: []string{"ldap://127.0.0.1:1389"},
			},
		},
	}
}

// restartBaselineLua builds the process-owned primary, hook, and named Lua fixtures.
func restartBaselineLua(artifacts restartBaselineArtifacts) *config.LuaSection {
	return &config.LuaSection{
		Config: &config.LuaConf{
			BackendNumberOfWorkers: 2, QueueLength: 8, HookVMPoolSize: 2,
			BackendScriptPath: artifacts.backendScript,
		},
		Hooks: []config.LuaHooks{{
			Location: "health", Method: "GET", ScriptPath: artifacts.hookScript,
		}},
		OptionalLuaBackends: map[string]*config.LuaConf{
			"named": {
				BackendNumberOfWorkers: 1, QueueLength: 4,
				BackendScriptPath: artifacts.namedBackendScript,
			},
		},
	}
}

// restartBaselineBackend constructs one exact ordered backend selector.
func restartBaselineBackend(t *testing.T, name string) *config.Backend {
	t.Helper()

	backend := &config.Backend{}
	if err := backend.Set(name); err != nil {
		t.Fatalf("set backend %q: %v", name, err)
	}

	return backend
}

// restartBaselineControl constructs one valid boot control selector.
func restartBaselineControl(t *testing.T, name string) *config.Control {
	t.Helper()

	control := &config.Control{}
	if err := control.Set(name); err != nil {
		t.Fatalf("set control %q: %v", name, err)
	}

	return control
}

// restartBaselineService constructs one valid boot service selector.
func restartBaselineService(t *testing.T, name string) *config.Service {
	t.Helper()

	service := &config.Service{}
	if err := service.Set(name); err != nil {
		t.Fatalf("set service %q: %v", name, err)
	}

	return service
}

// restartBaselineBool returns an independently addressable bool for pointer-valued config switches.
func restartBaselineBool(value bool) *bool {
	return &value
}

// newRestartBaselineCoordinator builds the real policyfx preflight around one baseline.
func newRestartBaselineCoordinator(
	t *testing.T,
	store *policyruntime.GenerationStore,
	configured config.File,
	validator RestartBaselineValidator,
) *Coordinator {
	t.Helper()

	return newRestartBaselineCoordinatorWithTransport(
		t,
		store,
		configured,
		validator,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{}, nil
		},
	)
}

// newRestartBaselineCoordinatorWithTransport builds the real preflight with an injected transport validator.
func newRestartBaselineCoordinatorWithTransport(
	t *testing.T,
	store *policyruntime.GenerationStore,
	configured config.File,
	validator RestartBaselineValidator,
	transport TransportCapabilitiesFactory,
) *Coordinator {
	t.Helper()

	coordinator, err := NewCoordinator(
		store,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&pluginloader.State{},
		unusedTokenFactory,
		unusedThrottlerFactory,
		transport,
		localization.NewMapCatalog(nil),
		mustStartupCatalog(t, configured, nil),
		validator,
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coordinator
}

// assertRestartBaselineRetainedGeneration verifies every published authority stayed on G1.
func assertRestartBaselineRetainedGeneration(
	t *testing.T,
	store *policyruntime.GenerationStore,
	active *policyruntime.Generation,
	activeConfig config.File,
	activeCatalog *policyruntime.TargetCatalog,
	activeApplication policyruntime.Application,
	activeBindings *policyruntime.BindingSet,
) {
	t.Helper()

	retained := store.Active()
	if retained != active || retained.ID() != 1 || retained.Config() != activeConfig {
		t.Fatalf("active generation/config = %p/%T, want exact G1 %p/%T", retained, retained.Config(), active, activeConfig)
	}

	if retained.Application() != activeApplication {
		t.Fatal("restart-bound drift replaced the G1 route/application authority")
	}

	if !reflect.DeepEqual(retained.TargetCatalog(), activeCatalog) {
		t.Fatal("restart-bound drift replaced the G1 target catalog")
	}

	if !reflect.DeepEqual(retained.Bindings(), activeBindings) {
		t.Fatal("restart-bound drift replaced the G1 resource bindings")
	}
}
