OpenTelemetry for Lua scripts (nauthilus_opentelemetry)

This module allows Lua scripts to create and control OpenTelemetry spans, set attributes/events/status, use baggage, and inject/extract trace headers. The module is request-scoped and becomes a no-op when tracing is disabled in configuration.

Loading
```lua
local otel = require("nauthilus_opentelemetry")
```

Feature detection
```lua
if not otel.is_enabled() then
  -- tracing disabled; skip expensive telemetry work
end
```

Creating spans
```lua
local tr = otel.tracer("nauthilus/policy")

-- Start/End manually
local sp = tr:start_span("operation", { kind = "internal", attributes = { ["peer.service"] = "example" } })
sp:add_event("started")
sp:end()

-- With convenience: with_span
tr:with_span("policy.evaluate", function(span)
  span:set_attributes({ ["key"] = "value", ["tries"] = 1, ["ok"] = true })
end, { kind = "client" })
```

Span methods
- `set_attribute(key, value)` — value can be string/number/boolean
- `set_attributes(table)` — bulk set attributes from a `{ key = value }` table
- `add_event(name, attributes?)`
- `set_status(code, description?)` — `code`: `ok` | `error` | `unset`
- `record_error(err_or_msg)` — marks span as error and records the error
- `end()`

Options for `start_span`/`with_span`
- `kind`: `internal` (default) | `client` | `server` | `producer` | `consumer`
- `attributes`: table of attributes `{ [string] = string|number|boolean }`
- `links`: array of `{ trace_id = "...", span_id = "...", attributes = { ... } }`

Baggage
```lua
otel.baggage_set("user.id", "42")
local v = otel.baggage_get("user.id")
for k, val in pairs(otel.baggage_all()) do print(k, val) end
otel.baggage_clear()
```

Header propagation (HTTP)
```lua
local headers = { }
otel.inject_headers(headers)   -- write trace headers into table
-- ... perform HTTP request using these headers ...

-- Extract example (restore context from headers)
otel.extract_headers(headers)
```

Semantic convenience helpers
```lua
local sem = otel.semconv
local attrs = sem.http_client_attrs({ method = "GET", url = "https://api.example.com", status_code = 200 })
-- Merge into span attributes
tr:with_span("http.call", function(span)
  span:set_attributes(attrs)
end, { kind = "client" })
```

Configuration toggle
- Controlled by `server.insights.tracing.enabled` in the config file. When disabled, the module is present but all operations are no-ops.

Notes
- The module follows the active request span created by `otelgin`. Child spans created in Lua will be attached to the current request’s context.
- Attribute tables ignore unsupported value types to keep encoding stable.
