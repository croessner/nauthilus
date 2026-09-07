package main

import (
	"crypto/sha256"
	"fmt"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type stateKeyspace struct{ builder pluginapi.RedisKeyBuilder }

type subjectKeyset struct{ State, Seen, Override string }

// audit retains one bounded operator receipt beside its exact opaque subject, independently of models.
func (k stateKeyspace) audit(tag string) string {
	return k.builder.Key("reputation:{" + tag + "}:operator-audit")
}

// subject keeps a model's state and deduplication set beside its model-independent override in one hash slot.
func (k stateKeyspace) subject(tag, model string) subjectKeyset {
	base := "reputation:{" + tag + "}:"
	return subjectKeyset{State: k.builder.Key(base + "state:" + model), Seen: k.builder.Key(base + "seen:" + model), Override: k.builder.Key(base + "override")}
}

// metadata returns the fixed same-slot allocation and model registration keys.
func (k stateKeyspace) metadata() []string {
	return k.builder.Keys("reputation:event:{manifest-meta}:allocation", "reputation:event:{manifest-meta}:models")
}

// shardPrefix isolates a fixed manifest shard without leaking source or event identifiers.
func shardPrefix(shard int) string { return fmt.Sprintf("reputation:event:{manifest-%02x}:", shard) }

// control returns the per-shard allocation fencing record used by every admission.
func (k stateKeyspace) control(shard int) string {
	return k.builder.Key(shardPrefix(shard) + "control")
}

// manifest derives fixed opaque allocation, control and source-quota keys in the same Cluster slot.
func (k stateKeyspace) manifest(allocation, source string) ([]string, int) {
	digest := sha256.Sum256([]byte(allocation))
	shard := int(digest[0]) % manifestShardCount
	prefix := shardPrefix(shard)

	return k.builder.Keys(prefix+"manifest:"+allocation, prefix+"control", prefix+"subjects:"+source, prefix+"events:"+source), shard
}

// shardBudget divides a global ceiling conservatively across fixed shards without a cross-slot transaction.
func shardBudget(total, shard int) int {
	result := total / manifestShardCount
	if shard < total%manifestShardCount {
		result++
	}

	return result
}
