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

function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_context")
    local nauthilus_context = require("nauthilus_context")

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    dynamic_loader("nauthilus_gluahttp")
    local http = require("glua_http")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    -- Get result table
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then
        rt = {}
    end

    local t = {}

    t.ip = request.client_ip

    local payload, json_encode_err = json.encode(t)
    nauthilus_util.if_error_raise(json_encode_err)

    nauthilus_prometheus.create_summary_vec(N .. "_duration_seconds", "HTTP request to the blocklist service", {"http"})

    local timer = nauthilus_prometheus.start_timer(N .. "_duration_seconds", {http="post"})
    local result, request_err = http.post(os.getenv("BLOCKLIST_URL"), {
        timeout = "10s",
        headers = {
            Accept = "*/*",
            ["User-Agent"] = "Nauthilus",
            ["Content-Type"] = "application/json",
        },
        body = payload,
    })
    nauthilus_prometheus.stop_timer(timer)
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

        return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_YES, nauthilus_builtin.FEATURE_RESULT_OK
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
