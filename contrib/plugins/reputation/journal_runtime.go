package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type observationJournal interface {
	enqueue(context.Context, string, manifestPayload, float64) error
}

type journalRuntime struct {
	client  *kgo.Client
	state   *stateOwner
	config  *journalConfig
	metrics *journalTelemetry
	cancel  context.CancelFunc
	codec   journalCodec
	timeout time.Duration
	done    chan struct{}
}

// newJournalRuntime creates one explicitly scoped TLS client for direct acknowledged production or consumption.
func newJournalRuntime(state *stateOwner, host pluginapi.Host) (*journalRuntime, error) {
	cfg := state.config.raw.Journal

	tlsConfig, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}

	timeout, err := time.ParseDuration(cfg.DeliveryTimeout)
	if err != nil {
		return nil, errConfiguration
	}

	client, err := kgo.NewClient(kgo.SeedBrokers(cfg.Brokers...), kgo.DialTLSConfig(tlsConfig),
		kgo.RequiredAcks(kgo.AllISRAcks()), kgo.MaxBufferedRecords(1024), kgo.MaxBufferedBytes(16*1024*1024),
		kgo.RecordDeliveryTimeout(max(time.Second, timeout)), kgo.ProducerBatchCompression(kgo.ZstdCompression()))
	if err != nil {
		return nil, errConfiguration
	}

	metrics, err := newJournalTelemetry(host.Metrics(pluginName))
	if err != nil {
		client.Close()
		return nil, err
	}

	runtime := &journalRuntime{client: client, state: state, config: cfg, timeout: timeout, metrics: metrics, done: make(chan struct{}),
		codec: journalCodec{tagger: state.planner.tagger, scope: state.config.raw.ManifestScope, topic: cfg.Topic}}

	return runtime, nil
}

// enqueue accepts an immutable contribution only after the broker acknowledges it.
func (j *journalRuntime) enqueue(ctx context.Context, allocation string, payload manifestPayload, expiry float64) error {
	if j.config.Role != journalProducer {
		return errStateUnavailable
	}

	frozen, err := json.Marshal(payload)
	if err != nil {
		return errManifestPlan
	}

	encoded, err := j.codec.encode(ctx, allocation, string(frozen), expiry)
	if err != nil {
		return err
	}

	return j.publish(ctx, allocation, encoded)
}

// publish requires all in-sync replica acknowledgement and exposes only a closed error class.
func (j *journalRuntime) publish(ctx context.Context, key string, value []byte) error {
	started := time.Now()

	defer func() {
		if j.metrics.delivery != nil {
			j.metrics.delivery.Observe(ctx, time.Since(started).Seconds())
		}
	}()

	sendContext, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()

	if err := j.client.ProduceSync(sendContext, &kgo.Record{Topic: j.config.Topic, Key: []byte(key), Value: value}).FirstErr(); err != nil {
		j.metrics.outcome.Add(ctx, journalOutcomeRetry)
		return errStateUnavailable
	}

	j.metrics.outcome.Add(ctx, "published")

	return nil
}

// start preserves both module cancellation and the host's supervised worker lifetime.
func (j *journalRuntime) start(host pluginapi.Host) {
	ctx, cancel := context.WithCancel(host.ServiceContext())
	j.cancel = cancel

	host.Go(ctx, "reputation-journal", func(hostContext context.Context) error {
		defer close(j.done)
		defer j.client.Close()

		stop := context.AfterFunc(hostContext, cancel)
		defer stop()

		if j.config.Role == journalProducer {
			<-ctx.Done()
			return nil
		}

		return j.consume(ctx)
	})
}

// journalPause bounds retry pressure without delaying cancellation.
func journalPause(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Second):
		return true
	}
}

// stop waits for cancellation-bound workers and client cleanup without retaining unacknowledged records.
func (j *journalRuntime) stop(ctx context.Context) error {
	j.cancel()

	select {
	case <-j.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// apply verifies a sealed complete plan and reuses atomic same-subject deduplication for every retry.
func (j *journalRuntime) apply(ctx context.Context, key string, value []byte) error {
	message, err := j.codec.decode(ctx, key, value, time.Now())
	if err != nil {
		return err
	}

	var payload manifestPayload
	if err := json.Unmarshal([]byte(message.Payload), &payload); err != nil || !j.state.validJournalPayload(payload) {
		return errManifestPlan
	}

	started := time.Now()
	result, err := j.state.applyManifest(ctx, payload, message.Expires)
	j.metrics.recordApplied(ctx, started, message.Expires, result.Applied, err)

	if err != nil {
		return err
	}

	j.metrics.outcome.Add(ctx, learningIngestionResult(result, nil))

	return nil
}

// quarantineReason distinguishes non-replayable evidence from transient storage or capacity failures.
func quarantineReason(err error) bool {
	return errors.Is(err, errManifestPlan) || errors.Is(err, errEventTime) || errors.Is(err, errModelMismatch)
}

// validJournalPayload requires bounded contributions to models explicitly active in this consumer generation.
func (s *stateOwner) validJournalPayload(payload manifestPayload) bool {
	if payload.Schema != manifestSchema || len(payload.Models) < 1 || len(payload.Models) > 2 {
		return false
	}

	for _, model := range payload.Models {
		if len(model.Subjects) < 1 || len(model.Subjects) > maximumExpandedSubjects || !s.hasJournalModel(model) {
			return false
		}
	}

	return true
}

// hasJournalModel refuses detached contributions outside the configured immutable model identities.
func (s *stateOwner) hasJournalModel(model manifestModel) bool {
	for _, active := range s.models {
		if active.id == model.ID && active.fingerprint == model.Fingerprint {
			return true
		}
	}

	return false
}
