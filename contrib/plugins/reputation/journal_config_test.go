package main

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// testJournalConfig supplies explicit deployment-owned transport values without opening connections.
func testJournalConfig() map[string]any {
	return map[string]any{
		"brokers": []any{"journal-kafka-bootstrap.kafka.svc.cluster.local:9093"},
		"role":    journalProducer, "topic": "reputation.prod", "quarantine_topic": "reputation.prod.quarantine",
		"group_id": "reputation.prod", "ca_file": "/tls/ca.crt", "certificate_file": "/tls/user.crt", "key_file": "/tls/user.key",
		"outbox_directory": "/outbox", "outbox_max_records": 10000, "outbox_max_bytes": 512 * 1024 * 1024, "delivery_timeout": "500ms",
	}
}

// TestJournalConfigurationDoesNotResetExistingScores separates transport deployment from scoring semantics.
func TestJournalConfigurationDoesNotResetExistingScores(t *testing.T) {
	raw := testConfigMap(t)
	original, err := compileModel(testConfig(t))
	requireNoError(t, err)

	raw["journal"] = testJournalConfig()
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	changed, err := compileModel(cfg)
	requireNoError(t, err)

	if original.fingerprint != changed.fingerprint {
		t.Fatal("enabling durable transport reset the reputation model")
	}
}

// TestJournalConfigurationRejectsUnsafeTransport prevents accidental plaintext, unbounded buffers and topic aliasing.
func TestJournalConfigurationRejectsUnsafeTransport(t *testing.T) {
	for _, test := range []struct {
		key   string
		value any
	}{
		{"role", "combined"}, {"ca_file", ""}, {"key_file", "relative.key"}, {"brokers", []any{"missing-port"}},
		{"quarantine_topic", "reputation.prod"}, {"outbox_max_records", 0}, {"outbox_max_bytes", 1},
		{"delivery_timeout", "0s"}, {"delivery_timeout", "11s"},
	} {
		t.Run(test.key, func(t *testing.T) {
			raw := testConfigMap(t)
			journal := testJournalConfig()
			journal[test.key] = test.value
			raw["journal"] = journal
			_, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireError(t, err)
		})
	}
}
