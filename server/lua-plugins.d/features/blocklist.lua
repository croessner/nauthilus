-- Copyright (C) 2024 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

local N = "blocklist"

local nauthilus_util = require("nauthilus_util")

local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_otel = require("nauthilus_opentelemetry")

local http = require("glua_http")
local json = require("json")

local HCCR = "http_client_concurrent_requests_total"

function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    -- Get result table
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then
        rt = {}
    end

    local t = {}

    t.ip = request.client_ip

    local payload, json_encode_err = json.encode(t)
    nauthilus_util.if_error_raise(json_encode_err)

    nauthilus_prometheus.increment_gauge(HCCR, { service = N })

    local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { http = "post" })
    local result, request_err

    if nauthilus_otel and nauthilus_otel.is_enabled() then
        local url = os.getenv("BLOCKLIST_URL")
        local tr = nauthilus_otel.tracer("nauthilus/lua/blocklist")
        tr:with_span("blocklist.http", function(span)
            span:set_attributes(nauthilus_otel.semconv.peer_service("http"))
            span:set_attributes(nauthilus_otel.semconv.http_client_attrs({ method = "POST", url = url }))

            -- Add missing standard attributes for Tempo Service Graph
            -- rpc.system + destination identity (server.address/server.port)
            local host, p = url:match("^https?://([^/:]+):?(%d*)")
            local port = tonumber(p) or (url:match("^https://") and 443 or 80)
            span:set_attributes({
                ["rpc.system"] = "http",
                ["server.address"] = host or "",
                ["server.port"] = port,
            })

            -- Propagate trace headers to the downstream service
            local headers = {
                Accept = "*/*",
                ["User-Agent"] = "Nauthilus",
                ["Content-Type"] = "application/json",
            }
            nauthilus_otel.inject_headers(headers)

            result, request_err = http.post(url, { timeout = "10s", headers = headers, body = payload })

            if request_err then
                span:record_error(tostring(request_err))
            end

            if result and result.status_code then
                span:set_attributes({ ["http.status_code"] = result.status_code })
                if result.status_code ~= 200 then
                    span:record_error("status " .. tostring(result.status_code))
                end
            end
        end, { kind = "client" })
    else
        result, request_err = http.post(os.getenv("BLOCKLIST_URL"), {
            timeout = "10s",
            headers = {
                Accept = "*/*",
                ["User-Agent"] = "Nauthilus",
                ["Content-Type"] = "application/json",
            },
            body = payload,
        })
    end

    nauthilus_prometheus.stop_timer(timer)
    nauthilus_prometheus.decrement_gauge(HCCR, { service = N })
    nauthilus_util.if_error_raise(request_err)

    if result.status_code ~= 200 then
        nauthilus_util.if_error_raise(N .. "_status_code=" .. tostring(result.status_code))
    end

    local response, err_jdec = json.decode(result.body)
    nauthilus_util.if_error_raise(err_jdec)

    if response.error then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_FAILURE
    end

    if response.found then
        if nauthilus_util.is_table(rt) then
            rt.feature_blocklist = true

            nauthilus_context.context_set("rt", rt)
        end

        nauthilus_builtin.custom_log_add(N .. "_ip", request.client_ip)
        nauthilus_builtin.status_message_set("IP address blocked")

        if nauthilus_otel and nauthilus_otel.is_enabled() then
            local tr = nauthilus_otel.tracer("nauthilus/lua/blocklist")
            tr:with_span("blocklist.evaluate", function(span)
                span:set_attributes({
                    ["peer.service"] = "blocklist",
                    ip = request.client_ip or "",
                })
                span:add_event("match", { rule = "ip" })
            end)
        end

        return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_YES, nauthilus_builtin.FEATURE_RESULT_OK
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
