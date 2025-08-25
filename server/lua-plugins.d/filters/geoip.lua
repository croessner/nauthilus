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

local N = "geoippolicyd"

local HCCR = "http_client_concurrent_requests_total"

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Check if the IP is routable at the very beginning
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Early termination for non-routable addresses while respecting the authentication result
    if not is_routable then
        if request.authenticated then
            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
        else
            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    local function add_custom_logs(object)
        for item, values in pairs(object) do
            if type(values) == "table" then
                local log_str = ""

                for _, value in pairs(values) do
                    if string.len(log_str) == 0 then
                        log_str = value
                    else
                        log_str = log_str .. "," .. value
                    end

                    nauthilus_builtin.custom_log_add(N .. "_" .. item, log_str)
                end
            end
        end
    end

    local function exists_in_table(tbl, element)
        for _, value in pairs(tbl) do
            if value == element then
                return true
            end
        end

        return false
    end

    if request.authenticated then
        dynamic_loader("nauthilus_context")
        local nauthilus_context = require("nauthilus_context")

        dynamic_loader("nauthilus_prometheus")
        local nauthilus_prometheus = require("nauthilus_prometheus")

        dynamic_loader("nauthilus_gluahttp")
        local http = require("glua_http")

        dynamic_loader("nauthilus_gll_json")
        local json = require("json")

        -- Short-lived local cache to reduce outbound GEOIP policy requests under load
        dynamic_loader("nauthilus_cache")
        local nauthilus_cache = require("nauthilus_cache")

        local t = {}

        t.key = "client"
        t.value = {
            address = request.client_ip,
            sender = request.account
        }

        local payload, json_encode_err = json.encode(t)
        nauthilus_util.if_error_raise(json_encode_err)

        local cache_key = "geoip:" .. (request.client_ip or "") .. ":" .. (request.account or "")
        local response = nauthilus_cache.cache_get(cache_key)

        if response == nil then
            nauthilus_prometheus.increment_gauge(HCCR, { service = N })

            local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { http = "post" })
            local  result, request_err = http.post(os.getenv("GEOIP_POLICY_URL"), {
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

            local decoded, err_jdec = json.decode(result.body)
            nauthilus_util.if_error_raise(err_jdec)
            response = decoded

            -- Cache for a short TTL (30s) to keep decisions fresh while reducing HTTP load
            nauthilus_cache.cache_set(cache_key, response, 30)
        end

        if response.err == nil then
            local current_iso_code = ""

            nauthilus_builtin.custom_log_add(N .. "_guid", response.guid)

            if response.object then
                add_custom_logs(response.object)

                -- Try to get all ISO country codes
                if nauthilus_util.is_table(response.object) then
                    local result_iso_codes = {}

                    for key, values in pairs(response.object) do
                        if key == "current_country_code" then
                            if nauthilus_util.is_string(values) then
                                current_iso_code = values
                            end
                        end

                        if key == "foreign_countries_seen" or key == "home_countries_seen" then
                            if nauthilus_util.is_table(values) then
                                for _, iso_code in ipairs(values) do
                                    if not exists_in_table(result_iso_codes, iso_code) then
                                        table.insert(result_iso_codes, iso_code)
                                    end
                                end
                            end
                        end
                    end

                    nauthilus_context.context_set(N .. "_iso_codes_seen", result_iso_codes)
                end
            end

            if response.object and nauthilus_util.is_table(response.object) and response.object.policy_reject then
                nauthilus_prometheus.increment_counter(N .. "_count", {
                    country = current_iso_code,
                    status = "reject",
                })

                nauthilus_builtin.custom_log_add(N, "blocked")

                -- Get result table
                local rt = nauthilus_context.context_get("rt")
                if rt == nil then
                    rt = {}
                end

                if nauthilus_util.is_table(rt) then
                    rt.filter_geoippolicyd = true
                    -- Enrich rt with geoip details
                    rt.geoip_info = {
                        guid = response.guid or "",
                        current_country_code = current_iso_code or "",
                        iso_codes_seen = nauthilus_context.context_get(N .. "_iso_codes_seen") or {},
                        status = "reject",
                    }
                    nauthilus_context.context_set("rt", rt)
                end

                nauthilus_builtin.status_message_set("Policy violation")

                return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
            end

            nauthilus_prometheus.increment_counter(N .. "_count", {
                country = current_iso_code,
                status = "accept",
            })

            -- Also enrich rt on accept for downstream context
            do
                local rt = nauthilus_context.context_get("rt") or {}
                if nauthilus_util.is_table(rt) then
                    rt.filter_geoippolicyd = true
                    rt.geoip_info = {
                        guid = response.guid or "",
                        current_country_code = current_iso_code or "",
                        iso_codes_seen = nauthilus_context.context_get(N .. "_iso_codes_seen") or {},
                        status = "accept",
                    }
                    nauthilus_context.context_set("rt", rt)
                end
            end
        else
            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_FAIL
        end
    else
        -- We must restore a failed authentication flag!
        return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- The request should be accepted
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
