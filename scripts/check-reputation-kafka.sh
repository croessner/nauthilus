#!/bin/sh
set -eu

# Each invocation owns a private Compose project and removes only that project's test resources.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
project="nauthilus-reputation-journal-test-$$"
compose_file="testdata/reputation-kafka/compose.yaml"

cleanup() {
    docker compose -p "$project" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
command -v redis-server >/dev/null
docker compose -p "$project" -f "$compose_file" up -d --wait --wait-timeout 120
GOEXPERIMENT=runtimesecret go test -mod=vendor -tags=reputation_integration,reputation_kafka_integration ./contrib/plugins/reputation -run 'TestReputation(Kafka|RedisJournal)' -count=1 -timeout=3m
