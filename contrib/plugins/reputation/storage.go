package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync/atomic"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	storageSnapshot        = "snapshot"
	storageOverrideWritten = "override_written"
	storageOverrideRead    = "override_read"
	storageOverrideMissing = "override_missing"
	storageOverrideDeleted = "override_deleted"

	storageActive    = "active"
	storageAdmitted  = "admitted"
	storageApplied   = "applied"
	storageDuplicate = "duplicate"
	taggerProbe      = "probe"
)

var (
	errStateUnavailable   = errors.New("reputation state unavailable")
	errEventConflict      = errors.New("reputation event conflict")
	errEventTime          = errors.New("reputation event time rejected")
	errModelMismatch      = errors.New("reputation model identity mismatch")
	errAllocationMismatch = errors.New("reputation allocation identity mismatch")
	errQuotaExceeded      = errors.New("reputation storage quota exceeded")
)

type stateOwner struct {
	config   *configuration
	planner  *manifestPlanner
	redis    pluginapi.Redis
	models   []*modelDefinition
	identity string
	keys     stateKeyspace
	ready    atomic.Bool
}

type metadataRequest struct {
	Models     map[string]string `json:"models"`
	Operation  string            `json:"operation"`
	Schema     string            `json:"schema"`
	Identity   string            `json:"identity"`
	Retention  float64           `json:"retention"`
	Shards     int               `json:"shards"`
	Generation int               `json:"generation"`
}

type controlRequest struct {
	Operation string `json:"operation"`
	Schema    string `json:"schema"`
	Identity  string `json:"identity"`
	Previous  string `json:"previous"`
}

// newStateOwner binds storage exclusively to host-provided primary, key and named-script facades.
func newStateOwner(cfg *configuration, tagger pluginapi.OpaqueIdentifierTagger, redis pluginapi.Redis) (*stateOwner, error) {
	if cfg == nil || redis == nil || redis.Write() == nil || redis.Keys() == nil || redis.Scripts() == nil {
		return nil, errStateUnavailable
	}

	models, err := compileModels(cfg)
	if err != nil {
		return nil, err
	}

	planner, err := newManifestPlanner(cfg, tagger, models)
	if err != nil {
		return nil, err
	}

	identity, err := planner.allocationIdentity(context.Background())
	if err != nil {
		return nil, err
	}

	return &stateOwner{config: cfg, planner: planner, redis: redis, models: models, identity: identity, keys: stateKeyspace{builder: redis.Keys()}}, nil
}

// start registers immutable models and activates all fenced shards before publishing writer readiness.
func (s *stateOwner) start(ctx context.Context) error {
	sources := reputationScripts()

	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if _, err := s.redis.Scripts().Upload(ctx, name, sources[name]); err != nil {
			return errStateUnavailable
		}
	}

	response, err := s.run(ctx, scriptMetadata, s.keys.metadata(), s.metadataRequest("activate"))
	if err != nil {
		return err
	}

	if len(response) != 2 || response[0] != storageActive {
		return errStateUnavailable
	}

	previous, ok := response[1].(string)
	if !ok {
		return errStateUnavailable
	}

	for shard := range manifestShardCount {
		_, err := s.run(ctx, scriptControl, []string{s.keys.control(shard)}, controlRequest{Operation: "activate", Schema: manifestSchema, Identity: s.identity, Previous: previous})
		if err != nil {
			return err
		}
	}

	s.ready.Store(true)

	return nil
}

// metadataRequest detaches only bounded model fingerprints and allocation protocol metadata.
func (s *stateOwner) metadataRequest(operation string) metadataRequest {
	models := make(map[string]string, len(s.models))
	for _, model := range s.models {
		models[model.id] = model.fingerprint
	}

	return metadataRequest{Operation: operation, Schema: manifestSchema, Identity: s.identity, Models: models, Shards: manifestShardCount,
		Retention: s.config.manifestTTL.Seconds(), Generation: s.config.raw.AllocationDrainGeneration}
}

// quiesce fences every shard before recording the start of the maximum-retention allocation-key drain.
func (s *stateOwner) quiesce(ctx context.Context) error {
	s.ready.Store(false)

	if _, err := s.run(ctx, scriptMetadata, s.keys.metadata(), s.metadataRequest("begin_drain")); err != nil {
		return err
	}

	for shard := range manifestShardCount {
		if _, err := s.run(ctx, scriptControl, []string{s.keys.control(shard)}, controlRequest{Operation: "drain", Schema: manifestSchema, Identity: s.identity}); err != nil {
			return err
		}
	}

	_, err := s.run(ctx, scriptMetadata, s.keys.metadata(), s.metadataRequest("finish_drain"))

	return err
}

// run routes every script through the host's primary-backed registry and exposes only closed failure classes.
func (s *stateOwner) run(ctx context.Context, name string, keys []string, request any) ([]any, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, errStateUnavailable
	}

	raw, err := s.redis.Scripts().Run(ctx, name, keys, string(encoded))
	if err != nil {
		return nil, errStateUnavailable
	}

	result, ok := raw.([]any)
	if !ok || len(result) == 0 {
		return nil, errStateUnavailable
	}

	status, ok := result[0].(string)
	if !ok {
		return nil, errStateUnavailable
	}

	if err := storageStatusError(status); err != nil {
		return nil, err
	}

	return result, nil
}

// storageStatusError preserves the closed state-machine outcomes without Redis keys or evidence in errors.
func storageStatusError(status string) error {
	switch status {
	case storageOverrideRead, storageOverrideMissing, storageOverrideWritten, storageOverrideDeleted, storageSnapshot, storageActive, "draining", storageAdmitted, storageApplied, storageDuplicate:
		return nil
	case "override_conflict":
		return errOverrideConflict
	case "event_conflict":
		return errEventConflict
	case "event_time":
		return errEventTime
	case "model_mismatch":
		return errModelMismatch
	case "allocation_mismatch", "allocation_draining":
		return errAllocationMismatch
	case "quota_exceeded":
		return errQuotaExceeded
	default:
		return errStateUnavailable
	}
}
