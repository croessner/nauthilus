package main

import (
	"context"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// consume restarts failed sessions at committed offsets; partially applied batches remain replayable.
func (j *journalRuntime) consume(ctx context.Context) error {
	for ctx.Err() == nil {
		err := j.consumeSession(ctx)
		if err != nil && ctx.Err() == nil {
			j.metrics.outcome.Add(ctx, journalOutcomeRetry)
		}

		if !journalPause(ctx) {
			break
		}
	}

	return nil
}

// consumeSession prevents rebalances during one bounded batch and never automatically commits fetched work.
func (j *journalRuntime) consumeSession(ctx context.Context) error {
	tlsConfig, err := j.config.tlsConfig()
	if err != nil {
		return err
	}

	client, err := kgo.NewClient(kgo.SeedBrokers(j.config.Brokers...), kgo.DialTLSConfig(tlsConfig),
		kgo.ConsumerGroup(j.config.GroupID), kgo.ConsumeTopics(j.config.Topic), kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(), kgo.RebalanceTimeout(time.Minute), kgo.FetchMaxBytes(4*1024*1024),
		kgo.FetchMaxPartitionBytes(maximumJournalRecordBytes), kgo.ConsumeStartOffset(kgo.NewOffset().AtStart()), kgo.ConsumeResetOffset(kgo.NoResetOffset()))
	if err != nil {
		return errConfiguration
	}

	defer client.CloseAllowingRebalance()

	for ctx.Err() == nil {
		fetches := client.PollRecords(ctx, 32)
		if len(fetches.Errors()) != 0 {
			return errStateUnavailable
		}

		records := fetches.Records()
		batchContext, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := j.consumeBatch(batchContext, client, records)

		cancel()
		client.AllowRebalance()

		if err != nil {
			return err
		}
	}

	return nil
}

// consumeBatch commits only after all fetched records have a score or durable quarantine receipt.
func (j *journalRuntime) consumeBatch(ctx context.Context, client *kgo.Client, records []*kgo.Record) error {
	for _, record := range records {
		err := j.apply(ctx, string(record.Key), record.Value)
		if quarantineReason(err) {
			err = j.quarantine(ctx, record)
		}

		if err != nil {
			return err
		}
	}

	if len(records) == 0 {
		return nil
	}

	if err := client.CommitRecords(ctx, records...); err != nil {
		return errStateUnavailable
	}

	return nil
}

// quarantine retains the original sealed evidence for explicit operator review without applying expired contributions.
func (j *journalRuntime) quarantine(ctx context.Context, record *kgo.Record) error {
	sendContext, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()

	quarantined := &kgo.Record{Topic: j.config.QuarantineTopic, Key: record.Key, Value: record.Value}
	if err := j.client.ProduceSync(sendContext, quarantined).FirstErr(); err != nil {
		return errStateUnavailable
	}

	j.metrics.outcome.Add(ctx, "quarantined")

	return nil
}
