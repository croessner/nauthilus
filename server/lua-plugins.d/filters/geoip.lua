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

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_context")
local nauthilus_context = require("nauthilus_context")

dynamic_loader("nauthilus_gll_http")
local http = require("http")

dynamic_loader("nauthilus_gll_json")
local json = require("json")

local client = http.client({
    timeout = 30,
    user_agent = "Nauthilus"
})

local N = "filter_geoippolicyd"

function nauthilus_call_filter(request)
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

    local ts = nauthilus_util.get_current_timestamp()
    if ts == nil then
        ts = "unknown"
    end

    if request.user_found and request.authenticated and not (request.no_auth or request.client_ip == "127.0.0.1") then
        local t = {}

        t.key = "client"
        t.value = {
            address = request.client_ip,
            sender = request.account
        }

        local payload, json_encode_err = json.encode(t)
        nauthilus_util.if_error_raise(json_encode_err)

        local geoip_request = http.request("POST", os.getenv("GEOIP_POLICY_URL"), payload)
        geoip_request:header_set("Content-Type", "application/json")

        local result, request_err = client:do_request(geoip_request)
        nauthilus_util.if_error_raise(request_err)

        if result.code ~= 202 then
            nauthilus_util.if_error_raise(N .. "_status_code=" .. tostring(result.code))
        end

        local response, err_jdec = json.decode(result.body)
        nauthilus_util.if_error_raise(err_jdec)

        if response.err == nil then
            nauthilus_builtin.custom_log_add(N .. "_guid", response.guid)

            if response.object then
                add_custom_logs(response.object)

                -- Try to get all ISO country codes
                if nauthilus_util.is_table(response.object) then
                    local result_iso_codes = {}

                    for key, values in pairs(response.object) do
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

            if not response.result then
                nauthilus_builtin.custom_log_add(N, "blocked")

                -- Get result table
                local rt = nauthilus_context.context_get("rt")
                if rt == nil then
                    rt = {}
                end
                if nauthilus_util.is_table(rt) then
                    rt.filter_geoippolicyd = true

                    nauthilus_context.context_set("rt", rt)
                end

                return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
            end
        else
            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_FAIL
        end
    else
        -- We must restore a failed authentication flag!
        if not request.authenticated then
            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- The request should be accepted
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
