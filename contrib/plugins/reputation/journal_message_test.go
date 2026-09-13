package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestJournalMessageBindsExpiryAndContribution prevents delayed retries from extending their safe deduplication window.
func TestJournalMessageBindsExpiryAndContribution(t *testing.T) {
	tagger := manifestTestTagger(t, false)
	plan := testManifestPlan(t, tagger, testObservation())
	codec := journalCodec{tagger: tagger, scope: "reputation-manifest", topic: "reputation.shadow"}
	expiry := float64(time.Now().Add(time.Hour).Unix())
	encoded, err := codec.encode(context.Background(), plan.AllocationTag, plan.Candidates[0].Payload, expiry)
	requireNoError(t, err)
	message, err := codec.decode(context.Background(), plan.AllocationTag, encoded, time.Now())
	requireNoError(t, err)

	if message.Payload != plan.Candidates[0].Payload || message.Expires != expiry {
		t.Fatal("journal changed the immutable contribution")
	}

	var envelope journalEnvelope
	requireNoError(t, json.Unmarshal(encoded, &envelope))
	envelope.Message.Expires += 3600
	tampered, err := json.Marshal(envelope)
	requireNoError(t, err)
	_, err = codec.decode(context.Background(), plan.AllocationTag, tampered, time.Now())
	requireError(t, err)
	_, err = codec.decode(context.Background(), "another-allocation", encoded, time.Now())
	requireError(t, err)

	otherTopic := codec
	otherTopic.topic = "reputation.prod"
	_, err = otherTopic.decode(context.Background(), plan.AllocationTag, encoded, time.Now())
	requireError(t, err)

	_, err = codec.decode(context.Background(), plan.AllocationTag, encoded, time.Now().Add(2*time.Hour))
	if err != errEventTime {
		t.Fatal("expired evidence was eligible for application")
	}
}
