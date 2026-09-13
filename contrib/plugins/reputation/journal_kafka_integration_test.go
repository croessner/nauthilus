//go:build reputation_integration && reputation_kafka_integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
)

const localJournalBroker = "127.0.0.1:19092"

// localJournalClient permits only the loopback broker owned by the integration Compose stack.
func localJournalClient(t *testing.T, options ...kgo.Opt) *kgo.Client {
	t.Helper()

	options = append([]kgo.Opt{kgo.SeedBrokers(localJournalBroker), kgo.RequiredAcks(kgo.AllISRAcks())}, options...)
	client, err := kgo.NewClient(options...)
	requireNoError(t, err)
	t.Cleanup(client.CloseAllowingRebalance)

	return client
}

// createJournalTestTopics creates uniquely named isolated event and quarantine topics.
func createJournalTestTopics(t *testing.T, client *kgo.Client) *journalConfig {
	t.Helper()

	name := fmt.Sprintf("nauthilus-integration-%d", time.Now().UnixNano())
	request := kmsg.NewPtrCreateTopicsRequest()
	request.Topics = []kmsg.CreateTopicsRequestTopic{
		{Topic: name, NumPartitions: 1, ReplicationFactor: 1},
		{Topic: name + ".quarantine", NumPartitions: 1, ReplicationFactor: 1},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	response, err := request.RequestWith(ctx, client)
	requireNoError(t, err)

	for _, topic := range response.Topics {
		if topic.ErrorCode != 0 {
			t.Fatalf("test topic creation failed with code %d", topic.ErrorCode)
		}
	}

	return &journalConfig{Topic: name, QuarantineTopic: name + ".quarantine", GroupID: name}
}

// testJournalCounter records only closed outcomes from integration-owned clients.
func testJournalCounter(t *testing.T) *telemetry.Counter {
	t.Helper()

	counter, err := telemetry.RegisterCounter(&metricCapture{}, "journal_total", "Journal integration outcomes.",
		telemetry.Dimension{Name: metricResult, Values: []string{"published", "outboxed", storageApplied, storageDuplicate, "retry", "quarantined", "outbox_full"}})
	requireNoError(t, err)

	return counter
}

// journalTestConsumer disables all automatic offset advancement for explicit restart assertions.
func journalTestConsumer(t *testing.T, cfg *journalConfig) *kgo.Client {
	t.Helper()

	return localJournalClient(t, kgo.ConsumerGroup(cfg.GroupID), kgo.ConsumeTopics(cfg.Topic),
		kgo.DisableAutoCommit(), kgo.BlockRebalanceOnPoll(), kgo.ConsumeStartOffset(kgo.NewOffset().AtStart()),
		kgo.ConsumeResetOffset(kgo.NoResetOffset()))
}

// journalTestFetch requires one actual broker delivery rather than treating an empty poll as success.
func journalTestFetch(t *testing.T, consumer *kgo.Client) []*kgo.Record {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	fetches := consumer.PollRecords(ctx, 1)
	if len(fetches.Errors()) != 0 || len(fetches.Records()) != 1 {
		t.Fatal("expected one broker-delivered journal record")
	}

	return fetches.Records()
}

// TestReputationKafkaOutboxRestartAndDuplicate proves durable recovery and exact Redis replay with a real broker.
func TestReputationKafkaOutboxRestartAndDuplicate(t *testing.T) {
	live := localJournalClient(t)
	journalConfig := createJournalTestTopics(t, live)
	redisClient, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	state, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, state.start(t.Context()))
	outboxDirectory := t.TempDir()
	outbox, err := openJournalOutbox(outboxDirectory, 8, 1024*1024)
	requireNoError(t, err)
	unavailable, err := kgo.NewClient(kgo.SeedBrokers("127.0.0.1:1"), kgo.RecordDeliveryTimeout(time.Second))
	requireNoError(t, err)
	t.Cleanup(unavailable.Close)

	runtime := &journalRuntime{client: unavailable, outbox: outbox, state: state, config: journalConfig,
		timeout: 200 * time.Millisecond, metrics: &journalTelemetry{outcome: testJournalCounter(t)},
		codec: journalCodec{tagger: tagger, scope: cfg.raw.ManifestScope, topic: journalConfig.Topic}}
	state.journal = runtime
	admitted := integrationObservation(t, cfg, tagger, "outbox-recovery")
	queued, err := state.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if !queued.Queued || queued.Applied != 0 {
		t.Fatal("broker outage did not retain durable acceptance")
	}

	runtime.outbox, err = openJournalOutbox(outboxDirectory, 8, 1024*1024)
	requireNoError(t, err)

	runtime.client = live
	runtime.timeout = 5 * time.Second
	requireNoError(t, runtime.outbox.drain(t.Context(), runtime.publish))
	verifyJournalConsumerRestart(t, runtime, redisClient)
}

// verifyJournalConsumerRestart replays an uncommitted delivery, then proves committed duplicates do not increment scores.
func verifyJournalConsumerRestart(t *testing.T, runtime *journalRuntime, redisClient *redis.Client) {
	t.Helper()
	first := journalTestConsumer(t, runtime.config)
	records := journalTestFetch(t, first)
	requireNoError(t, runtime.apply(t.Context(), string(records[0].Key), records[0].Value))
	first.CloseAllowingRebalance()

	restarted := journalTestConsumer(t, runtime.config)

	replayed := journalTestFetch(t, restarted)
	if replayed[0].Offset != records[0].Offset {
		t.Fatal("uncommitted delivery was skipped after consumer restart")
	}

	requireNoError(t, runtime.consumeBatch(t.Context(), restarted, replayed))
	restarted.AllowRebalance()
	requireNoError(t, runtime.publish(t.Context(), string(records[0].Key), records[0].Value))
	duplicate := journalTestFetch(t, restarted)
	requireNoError(t, runtime.consumeBatch(t.Context(), restarted, duplicate))
	restarted.AllowRebalance()

	message, err := runtime.codec.decode(t.Context(), string(records[0].Key), records[0].Value, time.Now())
	requireNoError(t, err)

	var payload manifestPayload

	requireNoError(t, json.Unmarshal([]byte(message.Payload), &payload))

	for _, model := range payload.Models {
		assertJournalSampleCounts(t, redisClient, runtime.state, model)
	}
}
