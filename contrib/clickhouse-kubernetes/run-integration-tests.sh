#!/usr/bin/env bash
# Runs the ClickHouse diagnostic contract integration tests against a disposable local ClickHouse container of the
# production image version. The container is removed on exit; no shared or production database is touched.
set -euo pipefail

image="${CLICKHOUSE_TEST_IMAGE:-clickhouse/clickhouse-server:25.8}"
name="nauthilus-clickhouse-it-$$"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cleanup() {
	docker rm -f "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "${name}" -p 127.0.0.1::8123 -e CLICKHOUSE_SKIP_USER_SETUP=1 \
	--ulimit nofile=262144:262144 "${image}" >/dev/null

port="$(docker port "${name}" 8123/tcp | head -n1 | awk -F: '{print $NF}')"
url="http://127.0.0.1:${port}/"

for _ in $(seq 1 60); do
	if curl -fsS "${url}?query=SELECT%201" >/dev/null 2>&1; then
		break
	fi
	sleep 1
done

cd "${root}"
export NAUTHILUS_CLICKHOUSE_TEST_URL="${url}"
GOEXPERIMENT=runtimesecret go test -count=1 -tags clickhouse_integration -run 'TestClickHouse' ./contrib/plugins/clickhouse/ "$@"
