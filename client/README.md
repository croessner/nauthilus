# Nauthilus Test Client

A CSV-driven test/load client for Nauthilus. It builds JSON requests compatible with `server/model/authdto/json_request.go` and validates responses.

## Features
- CSV input with columns like `username`, `password`, `client_ip`, `user_agent`, `protocol`, `method`, and SSL fields (`ssl`, `ssl_protocol`, `ssl_cipher`, `ssl_client_verify`, ...)
- Per-row expectation via `expected_ok` (boolean) column in the CSV
- Concurrency (`--concurrency`), rate limiting (`--rps`), jitter (`--jitter-ms`), and per-item delay (`--delay-ms`)
- Time/cycle control: run for a total duration (`--duration`, e.g. `5m`) looping over the CSV, or run a fixed number of loops (`--loops`)
- Optional shuffling, timeout control, extra headers
- Response validation against JSON field `{ "ok": true|false }` or, alternatively, via HTTP status

## Directory layout
```
client/
  main.go
  go.mod
  logins.csv   # example CSV
  README.md    # this file
server/
  lua-plugins.d/
    init/
      testing_csv_loader.lua
    backend/
      testing_csv_backend.lua
```

## CSV format
Required: a header line and the column `expected_ok`.

Example `client/logins.csv`:
```
username,password,client_ip,expected_ok,user_agent,protocol,method,ssl,ssl_protocol,ssl_cipher,ssl_client_verify,ssl_client_cn
alice,secret,198.51.100.10,true,MyTestClient/1.0,imap,PLAIN,on,TLSv1.3,TLS_AES_128_GCM_SHA256,SUCCESS,alice-cn
bob,badpass,198.51.100.11,false,MyTestClient/1.0,imap,PLAIN,on,TLSv1.3,TLS_AES_128_GCM_SHA256,FAIL,bob-cn
```
Unknown CSV columns are ignored. The client only sends keys that exist in the server's `authdto.Request` model. The username can also be taken from common synonyms (`account`, `user`, `login`, `email`) if `username` is missing.

CSV delimiter: auto-detected from the header (comma/semicolon/tab). You can override with `--csv-delim="," | ";" | "tab"`. Use `--csv-debug` to print detected headers and the first row.

## Build
Requirement: Go 1.25.x

```
cd client
go build -o nauthilus-testclient
```

## Run
```
./nauthilus-testclient \
  --csv ./logins.csv \
  --url http://localhost:8080/api/v1/auth/json \
  --concurrency 32 \
  --rps 200 \
  --jitter-ms 50 \
  --json-ok
```

- `--headers` allows additional headers separated by `||` (default ensures `Content-Type: application/json` and `Accept-Encoding: identity`).
- The client also sets `X-Forwarded-For` from the CSV column `client_ip` if present.
- `--basic-auth username:password` adds an `Authorization: Basic ...` header (unless already provided via `--headers`).
- `--method` sets the HTTP method (default: `POST`).
- `--max` limits how many CSV rows are used (after optional shuffle).
- When `--json-ok=false`, success is determined by HTTP status matching `--ok-status` (default: `200`).
- Parallelization knobs: `--max-parallel` (max parallel requests per item, 1=off) and `--parallel-prob` (probability 0..1 to parallelize an item).

NoAuth testing:

- `--random-no-auth` together with `--random-no-auth-prob=0..1` will randomly append the query `mode=no-auth` for
  requests whose CSV row has `expected_ok=true`. This allows mixing NoAuth requests into a normal run without changing
  the CSV. The flag will not override an explicit `mode` already present in the URL.

Rate limiting and pacing:
- `--rps` sets a global target rate. With `--duration`, items are paced across time while looping over the CSV.
- `--duration` runs continuously until the time elapses; `--loops` runs a fixed number of passes over the CSV.
- Optional `--delay-ms` and `--jitter-ms` add per-request delays.

Validation and logging:
- In JSON mode (`--json-ok`), the client reads `{ "ok": true|false }` from the response body.
- Otherwise it checks the HTTP status code.
- Verbose mode (`-v`) prints per-request outcomes; aggregated counters are printed at the end.

## Start server with test configuration
A working example configuration is available at `client/nauthilus.yml`. It enables the Lua backend path and loads the CSV via the init plugin into the Go cache.

Start the server with the test configuration:
```
TESTING_CSV=client/logins.csv \
./nauthilus -config client/nauthilus.yml -config-format yaml
```

Notes:
- `server.address` is set to `0.0.0.0:8080`. The client defaults to `http://localhost:8080/api/v1/auth/json`.
- The Lua backend is wired to `server/lua-plugins.d/backend/testing_csv_backend.lua` and loads `server/lua-plugins.d/init/testing_csv_loader.lua` at startup.
- Redis is expected locally at `127.0.0.1:6379` (see `server.redis`).

## cURL example (server)
```
curl -sS -X POST http://localhost:8080/api/v1/auth/json \
 -H 'Content-Type: application/json' \
 -H 'X-Forwarded-For: 198.51.100.10' \
 -d '{
  "username":"alice",
  "password":"secret",
  "client_ip":"198.51.100.10",
  "user_agent":"MyTestClient/1.0",
  "protocol":"imap",
  "method":"PLAIN",
  "ssl":"on",
  "ssl_protocol":"TLSv1.3",
  "ssl_cipher":"TLS_AES_128_GCM_SHA256",
  "ssl_client_verify":"SUCCESS",
  "ssl_client_cn":"alice-cn"
}'
```

## Notes
- The server response should include `{ "ok": true|false }` when `--json-ok` is used.
- Alternatively, with `--json-ok=false`, validation uses HTTP status (default: 200).
- Never use test data in production.

## Generate a large CSV (e.g., 10,000 rows)
The client can generate the CSV directly. All columns are filled appropriately and the file `client/logins.csv` will be overwritten.

Requirement: Go 1.25.x

Example (10,000 rows):
```
./nauthilus-testclient --generate-csv --generate-count 10000 --csv client/logins.csv
```

Or without building first:
```
cd client
go run . --generate-csv --generate-count 10000 --csv ./logins.csv
```

Details:
- Deterministic data is produced (`user00001` to `userNNNNN`).
- Columns: `username,password,client_ip,expected_ok,user_agent,protocol,method,ssl,ssl_protocol,ssl_cipher,ssl_client_verify,ssl_client_cn`.
- Values are deterministic (alternating `expected_ok`, rotating IPs in 198.51.100.0/24, alternating protocols/methods/SSL parameters).
- The Lua init loader (`server/lua-plugins.d/init/testing_csv_loader.lua`) and the Go client default to `client/logins.csv`. The generator writes exactly this format.

Note: This repository intentionally contains only a small example CSV. For load tests, use generation as shown above.
