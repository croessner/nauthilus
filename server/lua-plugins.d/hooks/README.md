# Hook Plugins for Nauthilus

This directory contains Lua hook plugins for the Nauthilus authentication system. Hook plugins are executed at specific points in the system's lifecycle or in response to specific events, allowing for custom processing, administrative functions, and integration with external systems.

## Available Plugins

### distributed-brute-force-admin.lua
Provides administrative functions for managing distributed brute force protection measures through an HTTP API.

**Features:**
- Retrieves security metrics from Redis for monitoring
- Includes warm-up diagnostics aligned with dynamic_response gating (progress by seconds/users/attempts, overall progress, warmed_up)
- Allows administrators to reset protection measures
- Provides account-specific management functions
- Returns structured JSON responses for integration with admin interfaces
- Supports multiple actions through HTTP query parameters

**Usage:**
Access the plugin through HTTP requests with the following query parameters:
- `action=get_metrics`: Retrieves current security metrics
  - Response includes `metrics` object with fields like:
    - `attempts`, `unique_ips`, `unique_users`, `ips_per_user`, `threat_level`
    - Warm-up (from dynamic_response): `warmup` object with `requirements` (seconds, min_users, min_attempts), `progress` (seconds, users, attempts, overall), `first_seen_ts`, `elapsed_seconds`, `warmed_up`. Legacy top-level fields: `warmup_progress` (overall 0.0-1.0), `warmup_complete` (boolean)
- `action=reset_protection`: Resets all protection measures (also resets `threat_level` to 0.0)
- `action=reset_account&username=<username>`: Resets protection for a specific account

Environment:
- `DYNAMIC_RESPONSE_WARMUP_SECONDS` (optional): gating minimum time since first activity (default 3600)
- `DYNAMIC_RESPONSE_WARMUP_MIN_USERS` (optional): minimum unique users observed (default 1000)
- `DYNAMIC_RESPONSE_WARMUP_MIN_ATTEMPTS` (optional): minimum total auth attempts observed (default 10000)

Example: `https://nauthilus-server/api/v1/custom/distributed-brute-force-admin?action=get_metrics`

### distributed-brute-force-test.lua
A testing tool for simulating distributed brute force attacks to verify that protection measures are working correctly.

**Features:**
- Simulates authentication attempts from multiple IPs
- Creates controlled test scenarios for security testing
- Configurable attack patterns and intensity
- Provides detailed logging of test activities
- Includes detection verification
- Includes warm-up diagnostics in responses (result.warmup: system_started_at, uptime_seconds, warmup_window_seconds, warmup_progress, warmup_complete)

**Usage:**
Access the plugin through HTTP requests with the following query parameters:
- `action=simulate_attack`: Simulates a distributed attack
- `action=check_detection`: Checks if an attack was detected
- `action=run_test`: Runs a complete test (simulation + detection check)
- `username=<username>`: Specifies the target account for the simulation
- `num_ips=<number>`: Sets the number of IPs to use in the attack (default: 20)
- `country_code=<code>`: Optional country code for regional attack simulation

Example: `https://nauthilus-server/api/v1/custom/distributed-brute-force-test?action=run_test&username=testuser&num_ips=30&country_code=RU`

### hello-world-request-dump.lua
A simple demonstration hook that returns an HTML page and dumps the incoming HTTP request.

**Features:**
- Renders a minimal, styled HTML page (no external assets required)
- Shows HTTP method and path
- Lists all request headers and their values
- Displays the request body
- Redacts password-like data in headers and body (e.g., password=xxxx)
- Uses the new nauthilus_http_response API to set headers, status and body

**Usage:**
- Typical endpoint: GET /api/v1/custom/hello-world-request-dump
- Send any request; the page will display all received data

Example: `https://nauthilus-server/api/v1/custom/hello-world-request-dump`

Note: Sensitive fields that look like passwords are masked for safety in the output.

### dovecot-session-cleaner.lua
Manages Dovecot authentication sessions, cleaning up expired sessions and maintaining session data.

**Features:**
- Periodically cleans up expired Dovecot authentication sessions
- Maintains session data in Redis with appropriate TTLs
- Provides statistics on active and expired sessions
- Optimizes Redis memory usage by removing unnecessary data
- Configurable Redis pool

**Usage:**
The plugin runs automatically when triggered by Dovecot session events. You can configure it through environment variables:
- `CUSTOM_REDIS_POOL_NAME`: The name of the Redis pool to use (defaults to "default" if not specified)

### clickhouse-query.lua
Provides a safe, read-only HTTP interface to query data stored in ClickHouse that was inserted by the clickhouse.lua post-action.

Features:
- Supports limited, whitelisted queries to prevent arbitrary SQL:
  - action=recent&limit=N
  - action=by_user&username=<user>&limit=N
  - action=by_ip&ip=<ip>&limit=N
- Uses glua_http (cjoudrey/gluahttp) for HTTP GET requests to ClickHouse.
- Returns raw ClickHouse JSON (FORMAT JSON) inside the result table for your frontend to render.

Environment:
- CLICKHOUSE_SELECT_BASE: Base URL of ClickHouse HTTP endpoint, e.g. http://clickhouse:8123
- CLICKHOUSE_TABLE: Target table (default nauthilus.failed_logins)
- CLICKHOUSE_USER / CLICKHOUSE_PASSWORD: Optional credentials via X-ClickHouse-User/Key headers

Examples:
- GET /api/v1/custom/clickhouse-query?action=recent&limit=100
- GET /api/v1/custom/clickhouse-query?action=by_user&username=alice@example.com&limit=200
- GET /api/v1/custom/clickhouse-query?action=by_ip&ip=203.0.113.10&limit=100

Security notes:
- Query type is restricted to a small, whitelisted set; inputs are minimally sanitized.
- Limit is clamped server-side (default 100, max 1000) to avoid heavy queries.

## Configuring Hooks in nauthilus.yml

To use the hooks in this directory, you need to configure them in your nauthilus.yml configuration file. Hooks are configured in the `lua.custom_hooks` section of the configuration file.

### Configuration Structure

Each hook requires the following configuration:

```yaml
lua:
  custom_hooks:
    - http_location: "hook-name"      # The URL path for the hook (relative to /api/v1/custom/)
      http_method: "HTTP_METHOD"      # The HTTP method (GET, POST, PUT, DELETE, PATCH)
      script_path: "/path/to/hook.lua" # Full path to the Lua script
      roles: ["role1", "role2"]       # Optional: List of roles that can access this hook when JWT auth is enabled
```

### Example Configuration

Here's an example configuration for the hooks described in this README:

```yaml
lua:
  custom_hooks:
    - http_location: "distributed-brute-force-admin"
      http_method: "POST"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/distributed-brute-force-admin.lua"
      roles: ["admin", "security"]

    - http_location: "distributed-brute-force-test"
      http_method: "POST"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/distributed-brute-force-test.lua"
      roles: ["admin", "security"]

    - http_location: "hello-world-request-dump"
      http_method: "GET"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/hello-world-request-dump.lua"
      roles: ["admin"]
```

### Access Control with JWT Authentication

When JWT authentication is enabled in Nauthilus, you can restrict access to hooks based on user roles:

1. Define the required roles in the `roles` array for each hook
2. Users must have at least one of the specified roles in their JWT token to access the hook
3. If no roles are specified, any authenticated user can access the hook
4. If JWT authentication is not enabled, role restrictions are ignored

### Enabling/Disabling All Custom Hooks

You can disable all custom hooks by setting `custom_hooks: false` in the `server.disabled_endpoints` section:

```yaml
server:
  disabled_endpoints:
    custom_hooks: true  # Disables all custom hooks
```


### http-head-get-demo.lua
A minimal demo hook to simulate and test HEAD and GET requests on the same endpoint.

Features:
- Responds to GET with text/plain body and 200 status
- Responds to HEAD with the same headers (including Content-Length) but no body
- Demonstrates usage of nauthilus_http_request + nauthilus_http_response

Usage:
- Configure the same http_location twice, once for GET and once for HEAD, both pointing to this script

Example:

```yaml
lua:
  custom_hooks:
    - http_location: "http-head-get-demo"
      http_method: "GET"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/http-head-get-demo.lua"
      roles: ["admin"]

    - http_location: "http-head-get-demo"
      http_method: "HEAD"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/http-head-get-demo.lua"
      roles: ["admin"]
```

Endpoint examples:
- GET /api/v1/custom/http-head-get-demo
- HEAD /api/v1/custom/http-head-get-demo


### dynamic-textmap-demo.lua
A Redis-backed demo hook that serves dynamic text/plain content suitable for consumers like Rspamd. It shows how to implement GET/HEAD on the same endpoint with proper caching headers and rotating content.

Features:
- Returns text/plain; GET sends the body, HEAD returns headers only
- Rotates content on a TTL window (default 60s) using Redis
- Sets standard headers for caches/clients: Content-Type, Cache-Control: no-cache,
  ETag (W/"v<version>-<len>"), Last-Modified (RFC 1123)
- Designed as a minimal template for building dynamic maps

Environment:
- CUSTOM_REDIS_POOL_NAME (optional): Redis pool name to use (default: "default")
- TEXTMAP_DEMO_TTL_SECONDS (optional): TTL/rotation window in seconds (default: 60)

Redis keys used:
- ntc:demo:textmap:content        (content, with TTL)
- ntc:demo:textmap:version        (monotonically increasing version)
- ntc:demo:textmap:last_modified  (unix timestamp, with TTL)

Usage:
- Configure the same http_location twice (GET and HEAD), both pointing to this script.

Example configuration:

```yaml
lua:
  custom_hooks:
    - http_location: "dynamic-textmap-demo"
      http_method: "GET"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/dynamic-textmap-demo.lua"
      roles: ["admin"]

    - http_location: "dynamic-textmap-demo"
      http_method: "HEAD"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/dynamic-textmap-demo.lua"
      roles: ["admin"]
```

Example requests:
- GET  /api/v1/custom/dynamic-textmap-demo
- HEAD /api/v1/custom/dynamic-textmap-demo

Example response body (GET):
```
# dynamic-textmap-demo
# version: 123
# generated_at: Fri, 05 Sep 2025 10:15:00 GMT
# This list rotates every TTL window; use ETag/Last-Modified for caching.
example.com
rotate-3.example
hash-1a2b3c4d
```

Notes:
- Clients can use ETag or Last-Modified to avoid re-downloading unchanged content within a TTL window.
- This is a demo; adapt key names, structure, and rotation logic for production needs.
