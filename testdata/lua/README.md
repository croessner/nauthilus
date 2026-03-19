# Lua Script Testing Examples

This directory contains example Lua scripts and mock data files for testing Nauthilus Lua callbacks.

## Directory Structure

```
testdata/lua/
├── README.md                    # This file
├── example_filter.lua           # Example filter script
├── example_feature.lua          # Example feature script
├── example_action.lua           # Example action script
├── example_backend.lua          # Example backend script
├── example_hook.lua             # Example hook script
├── example_backend_ldap.lua     # LDAP backend example
├── example_backend_db.lua       # DB backend example
├── filter_test.json             # Mock data for filter tests
├── feature_test.json            # Mock data for feature tests
├── action_test.json             # Mock data for action tests
├── backend_test.json            # Mock data for backend tests
├── hook_test.json               # Mock data for hook tests
├── backend_ldap_test.json       # Mock data for LDAP backend test
└── backend_db_test.json         # Mock data for DB backend test
```

## Running Tests

### Basic Usage

Test a Lua script without mock data:

```bash
./nauthilus --test-lua testdata/lua/example_filter.lua --test-callback filter
```

### With Mock Data

Test a Lua script with mock data from JSON file:

```bash
./nauthilus --test-lua testdata/lua/example_filter.lua \
            --test-callback filter \
            --test-mock testdata/lua/filter_test.json
```

### New LDAP and DB Examples

```bash
./nauthilus --test-lua testdata/lua/example_backend_ldap.lua \
            --test-callback backend \
            --test-mock testdata/lua/backend_ldap_test.json

./nauthilus --test-lua testdata/lua/example_backend_db.lua \
            --test-callback backend \
            --test-mock testdata/lua/backend_db_test.json
```

### Callback Types

The `--test-callback` flag accepts the following values:

- **filter**: Tests filter scripts (returns integer: -1 reject, 0 accept, >0 custom)
- **feature**: Tests feature scripts (returns boolean)
- **action**: Tests action scripts (returns boolean or nil)
- **backend**: Tests backend authentication scripts (returns backend result table)
- **hook**: Tests HTTP hook scripts (returns nil or result table)

## Mock Data Format

Mock data files are JSON files that define:

### Context Mock

Simulates the `nauthilus_context` module with request data:

```json
{
  "context": {
    "username": "testuser@example.com",
    "password": "password",
    "client_ip": "192.168.1.100",
    "service": "imap",
    "protocol": "plain"
  }
}
```

### Redis Mock

Simulates Redis responses for the `nauthilus_redis` module:

```json
{
  "redis": {
    "responses": {
      "key1": "value1",
      "key2": 123,
      "key3": {"json": "data"}
    }
  }
}
```

### LDAP Mock

Simulates LDAP responses for the `nauthilus_ldap` module:

```json
{
  "ldap": {
    "search_result": {
      "uid": ["uid-1"],
      "mail": ["user@example.com"]
    },
    "modify_ok": true,
    "endpoint_host": "ldap.example.internal",
    "endpoint_port": 389
  }
}
```

### DB Mock

In `--test-lua` mode, `require("db")` always resolves to the in-memory DB mock,
independent of driver/DSN (`mock://`, `mysql://`, `postgres://`, ...):

```json
{
    "db": {}
}
```

Optional error injection:

```json
{
    "db": {
        "open_error": "mock open failed",
        "exec_error": "mock exec failed",
        "query_error": "mock query failed"
    }
}
```

Optional strict call expectations (order-sensitive):

```json
{
  "db": {
    "expected_calls": [
      {"method": "open"},
      {"method": "exec", "query_contains": "create table"},
      {"method": "exec", "query_contains": "insert into"},
      {"method": "query", "query_contains": "select"},
      {"method": "close"}
    ]
  }
}
```

### Expected Output

Defines expected test results for validation:

```json
{
    "expected_output": {
        "backend_result": true,
        "error_expected": false
    }
}
```

## Available Mock Modules

The test environment provides mock implementations of these Nauthilus modules:

- `nauthilus_context`
- `nauthilus_redis`
- `nauthilus_backend_result`
- `nauthilus_http_request`
- `nauthilus_http_response`
- `nauthilus_ldap`
- `nauthilus_dns`
- `nauthilus_opentelemetry`
- `nauthilus_brute_force`
- `nauthilus_psnet`
- `nauthilus_util`
- `nauthilus_cache`
- `nauthilus_log`

Additionally, test mode preloads the same core Lua extras as runtime for script compatibility:

- `gopher-lua-libs` modules (for example `db`, `json`, `yaml`, `http`, ...)
- `glua_crypto`
- `glua_http`

## CI/CD Integration

You can integrate Lua script tests into your CI/CD pipeline:

```bash
#!/bin/bash
# run-lua-tests.sh

set -euo pipefail

run_test() {
  local script="$1"
  local callback="$2"
  local mock="$3"

  echo "Testing $script..."
  ./nauthilus/bin/nauthilus --test-lua "$script" --test-callback "$callback" --test-mock "$mock"
}

run_test testdata/lua/example_filter.lua filter testdata/lua/filter_test.json
run_test testdata/lua/example_feature.lua feature testdata/lua/feature_test.json
run_test testdata/lua/example_action.lua action testdata/lua/action_test.json
run_test testdata/lua/example_backend.lua backend testdata/lua/backend_test.json
run_test testdata/lua/example_hook.lua hook testdata/lua/hook_test.json
run_test testdata/lua/example_backend_ldap.lua backend testdata/lua/backend_ldap_test.json
run_test testdata/lua/example_backend_db.lua backend testdata/lua/backend_db_test.json
```

## Debugging Tips

1. Enable debug mode in mock data: set `"debug": true` in `context`.
2. Check logs: the test runner captures and prints Lua log output.
3. Validate return types: callback return types must match the callback category.
4. Use `expected_output`: define strict assertions for result and logs.
5. Start small and extend incrementally.
