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

-- Shared helpers for filter and action
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

-- Accept only ISO-3166-1 alpha-2 (two uppercase letters).
-- Note: We intentionally do NOT sanitize custom logs to allow seeing raw values like "N/A" in logs.
local function normalize_iso(code)
    if type(code) ~= "string" then return nil end
    -- trim whitespace and uppercase
    local c = code:match("^%s*(.-)%s*$"):upper()
    if c:match("^[A-Z][A-Z]$") then return c end
    return nil
end

local function build_payload_and_cache_key(request)
    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    local acc = request.account
    local sender = (acc ~= nil and acc ~= "" and acc) or "unknown"

    local t = {}
    t.key = "client"
    t.value = { address = request.client_ip, sender = sender }

    local payload, json_encode_err = json.encode(t)
    nauthilus_util.if_error_raise(json_encode_err)

    local cache_key = "geoip:" .. (request.client_ip or "") .. ":" .. (request.account or "")

    return payload, cache_key
end

local function http_geoip_request(url, payload)
    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    dynamic_loader("nauthilus_gluahttp")
    local http = require("glua_http")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    nauthilus_prometheus.increment_gauge(HCCR, { service = N })
    local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { http = "post" })

    local result, request_err = http.post(url, {
        timeout = "10s",
        headers = { Accept = "*/*", ["User-Agent"] = "Nauthilus", ["Content-Type"] = "application/json" },
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

    return decoded
end

local function process_response_and_context(response)
    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_context")
    local nauthilus_context = require("nauthilus_context")

    local current_iso_code = ""

    nauthilus_builtin.custom_log_add(N .. "_guid", response.guid)

    if response.object then
        -- Keep logs raw to allow visibility of placeholders like "N/A"
        add_custom_logs(response.object)
        if nauthilus_util.is_table(response.object) then
            local result_iso_codes = {}
            for key, values in pairs(response.object) do
                if key == "current_country_code" then
                    if nauthilus_util.is_string(values) then
                        local norm = normalize_iso(values)
                        if norm then
                            current_iso_code = norm
                        else
                            current_iso_code = ""
                        end
                    end
                end

                if key == "foreign_countries_seen" or key == "home_countries_seen" then
                    if nauthilus_util.is_table(values) then
                        for _, iso_code in ipairs(values) do
                            local norm = normalize_iso(iso_code)
                            if norm and not exists_in_table(result_iso_codes, norm) then
                                table.insert(result_iso_codes, norm)
                            end
                        end
                    end
                end
            end

            -- Fallback: if union of seen lists is empty, include current country code (if valid)
            if (#result_iso_codes == 0) and (current_iso_code ~= nil and current_iso_code ~= "") then
                table.insert(result_iso_codes, current_iso_code)
            end

            nauthilus_context.context_set(N .. "_iso_codes_seen", result_iso_codes)
        end
    end

    return current_iso_code
end

local function write_rt_geoip(rt, guid, current_iso_code, iso_codes_seen, status, is_filter)
    rt.filter_geoippolicyd = is_filter or false
    rt.geoip_info = {
        guid = guid or "",
        current_country_code = current_iso_code or "",
        iso_codes_seen = iso_codes_seen or {},
    }

    if status ~= nil then
        rt.geoip_info.status = status
    end
end

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Never run the GeoIP policy service for unauthenticated users!
    if not request.authenticated then
        -- Do not treat as reject; simply accept (no decision)
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
        -- Never reject for non-routable addresses here; no decision
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    dynamic_loader("nauthilus_context")
    local nauthilus_context = require("nauthilus_context")

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    -- Short-lived local cache to reduce outbound GEOIP policy requests under load
    dynamic_loader("nauthilus_cache")
    local nauthilus_cache = require("nauthilus_cache")

    local payload, base_cache_key = build_payload_and_cache_key(request)
    -- Use a dedicated namespace for filter cache to avoid mixing with action cache
    local cache_key = "policy:" .. base_cache_key
    local response = nauthilus_cache.cache_get(cache_key)

    if response == nil then
        response = http_geoip_request(os.getenv("GEOIP_POLICY_URL"), payload)
        nauthilus_cache.cache_set(cache_key, response, 30)
    end

    if response.err == nil then
        local current_iso_code = process_response_and_context(response)
        local iso_seen = nauthilus_context.context_get(N .. "_iso_codes_seen") or {}

        if response.object and response.object.policy_reject then
            nauthilus_prometheus.increment_counter(N .. "_count", { country = current_iso_code, status = "reject" })
            nauthilus_builtin.custom_log_add(N, "blocked")

            local rt = nauthilus_context.context_get("rt") or {}
            if nauthilus_util.is_table(rt) then
                write_rt_geoip(rt, response.guid, current_iso_code, iso_seen, "reject", true)
                nauthilus_context.context_set("rt", rt)
            end

            nauthilus_builtin.status_message_set("Policy violation")

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end

        nauthilus_prometheus.increment_counter(N .. "_count", { country = current_iso_code, status = "accept" })

        local rt = nauthilus_context.context_get("rt") or {}
        if nauthilus_util.is_table(rt) then
            write_rt_geoip(rt, response.guid, current_iso_code, iso_seen, "accept", true)
            nauthilus_context.context_set("rt", rt)
        end
    else
        if not request.authenticated then
            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_FAIL
        end

        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_FAIL
    end

    -- Preserve original authentication result semantics: if the request is not authenticated,
    -- keep the REJECT flag so upstream logic can maintain failed-auth state. Otherwise ACCEPT.
    if request.authenticated then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    else
        return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
    end
end

function nauthilus_call_action(request)
    local nauthilus_util = require("nauthilus_util")

    -- Skip non-routable IPs quickly; nothing to store
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    if not is_routable then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    dynamic_loader("nauthilus_context")
    local nauthilus_context = require("nauthilus_context")

    dynamic_loader("nauthilus_cache")
    local nauthilus_cache = require("nauthilus_cache")

    -- Build payload and a dedicated cache key for info-mode to avoid mixing with policy cache
    local payload, base_cache_key = build_payload_and_cache_key(request)
    local cache_key = "info:" .. base_cache_key

    local response = nauthilus_cache.cache_get(cache_key)
    if response == nil then
        -- Append info=1 to URL (preserve existing query if present)
        local base_url = os.getenv("GEOIP_POLICY_URL")
        local sep = string.find(base_url or "", "?", 1, true) and "&" or "?"
        local url = (base_url or "") .. sep .. "info=1"

        response = http_geoip_request(url, payload)

        -- Short TTL to keep fresh but reduce HTTP load
        nauthilus_cache.cache_set(cache_key, response, 30)
    end

    if response and response.err == nil then
        local current_iso_code = process_response_and_context(response)
        local iso_seen = nauthilus_context.context_get(N .. "_iso_codes_seen") or {}

        -- Only write info into rt, no status
        local rt = nauthilus_context.context_get("rt") or {}
        if nauthilus_util.is_table(rt) then
            write_rt_geoip(rt, response.guid, current_iso_code, iso_seen, nil, false)

            nauthilus_context.context_set("rt", rt)
        end
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
