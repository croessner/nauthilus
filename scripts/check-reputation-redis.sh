#!/bin/sh
set -eu

# Integration tests own private socket-only Redis processes; no live endpoint is accepted.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
export GOEXPERIMENT=runtimesecret
go test -mod=vendor -tags=reputation_integration ./contrib/plugins/reputation -run TestReputationRedis -count=1 -timeout=2m
