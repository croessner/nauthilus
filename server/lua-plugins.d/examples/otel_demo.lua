-- Example: OpenTelemetry from Lua in Nauthilus

local otel = require("nauthilus_opentelemetry")

if not otel.is_enabled() then
  return -- no-op when tracing is disabled
end

local tr = otel.tracer("nauthilus/example")

tr:with_span("example.root", function(span)
  span:set_attributes({ ["example"] = true })

  -- Child span with client kind and semantic attributes
  tr:with_span("http.call", function(child)
    child:set_attributes(otel.semconv.peer_service("http"))
    child:set_attributes(otel.semconv.http_client_attrs({ method = "GET", url = "https://example.org" }))
    child:add_event("request.sent")
    -- simulate work
  end, { kind = "client" })

end)
