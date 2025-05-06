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

local N = "neural"

local HCCR = "http_client_concurrent_requests_total"

function nauthilus_call_neural_network(request)
    if request.no_auth then
        return
    end

    local nauthilus_util = require("nauthilus_util")

    -- Check if the IP is routable at the very beginning
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Early termination for non-routable addresses while respecting the authentication result
    if not is_routable then
        return
    end

    local logs = {}

    logs.caller = N .. ".lua"
    logs.level = "info"

    -- For non-authenticated users, we still need to get the country code
    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    dynamic_loader("nauthilus_gluahttp")
    local http = require("glua_http")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    local t = {}

    t.key = "client"
    t.value = {
        address = request.client_ip,
        sender = request.username
    }

    local payload, json_encode_err = json.encode(t)
    nauthilus_util.if_error_raise(json_encode_err)

    nauthilus_prometheus.increment_gauge(HCCR, { service = N })

    local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { http = "post" })
    local result, request_err = http.post(os.getenv("GEOIP_POLICY_URL") .. "?info=1", {
        timeout = "10s",
        headers = {
            Accept = "*/*",
            ["User-Agent"] = "Nauthilus",
            ["Content-Type"] = "application/json",
        },
        body = payload,
    })

    nauthilus_prometheus.stop_timer(timer)
    nauthilus_prometheus.decrement_gauge(HCCR, { service = N })
    nauthilus_util.if_error_raise(request_err)

    if result.status_code ~= 202 then
        nauthilus_util.if_error_raise(N .. "_status_code=" .. tostring(result.status_code))
    end

    local response, err_jdec = json.decode(result.body)
    nauthilus_util.if_error_raise(err_jdec)

    if response.err == nil then
        local current_iso_code = ""

        if response.object then
            -- Try to get the ISO country code
            if nauthilus_util.is_table(response.object) then
                for key, values in pairs(response.object) do
                    if key == "current_country_code" then
                        if nauthilus_util.is_string(values) then
                            current_iso_code = values
                        end
                    end
                end
            end
        end

        -- If country code is empty, set it to "unknown" (we know IP is routable)
        if current_iso_code == "" then
            current_iso_code = "unknown"
        end

        nauthilus_builtin.custom_log_add("country_code", current_iso_code)

        local client_host = request.client_hostname
        local client_id = request.client_id
        local user_agent = request.user_agent

        if not client_host or client_host == "" then
            client_host = "unknown"
        end

        if not client_id or client_id == "" then
            client_id = "unknown"
        end

        if not user_agent or user_agent == "" then
            user_agent = "unknown"
        end

        -- Add country code to neural network
        dynamic_loader("nauthilus_neural")
        local nauthilus_neural = require("nauthilus_neural")

        -- Add country code as a feature for non-authenticated users
        -- Using the actual country code retrieved from the GeoIP service
        local additional_features = {
            country_code = current_iso_code,
            client_host = client_host,
            client_id = client_id,
            user_agent = user_agent,
        }

        for k, v in pairs(additional_features) do
            logs[k] = v

            nauthilus_builtin.custom_log_add(N .. "_" .. k, v)
        end

        nauthilus_util.print_result({ log_format = "json"}, logs)

        -- Add to neural network
        nauthilus_neural.add_additional_features(additional_features)
    end

    return
end
