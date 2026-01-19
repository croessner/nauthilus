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

local N = "telegram"

local nauthilus_util = require("nauthilus_util")

local nauthilus_password = require("nauthilus_password")
local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")

local http = require("http")
local telegram = require("telegram")
local template = require("template")

local HCCR = "http_client_concurrent_requests_total"

local TELEGRAM_PASSWORD = nauthilus_util.getenv("TELEGRAM_PASSWORD", "")
local TELEGRAM_CHAT_ID = tonumber(nauthilus_util.getenv("TELEGRAM_CHAT_ID", "0")) or 0

function nauthilus_call_action(request)
    if request.no_auth then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    local send_message = false
    local pwnd_info = "n/a"
    local headline = "Information"
    local log_prefix = ""
    local brute_force_bucket = "n/a"
    local password_hash = "n/a"
    local ts

    -- Get result table
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then
        rt = {}
    end

    if nauthilus_util.is_table(rt) and nauthilus_util.table_length(rt) > 0 then
        -- brute_force_haproxy
        if rt.brute_force_haproxy then
            send_message = true
            headline = "Brute force"
            log_prefix = "brute_force_"
            if request.brute_force_bucket and request.brute_force_bucket ~= "" then
                brute_force_bucket = request.brute_force_bucket
            end
        end

        -- feature_haproxy (not part of demo plugins)
        if rt.feature_haproxy then
            send_message = true
            if request.feature and request.feature ~= "" then
                headline = "Feature " .. request.feature .. " triggered"
                log_prefix = request.feature .. "_"
            else
                headline = "Feature triggered"
                log_prefix = "feature_"
            end
        end

        -- feature_blocklist
        if rt.feature_blocklist then
            send_message = true
            headline = "Feature " .. request.feature .. " (blocklist) triggered"
            log_prefix = request.feature .. "_"
        end

        -- feature_failed_login_hotspot
        if rt.feature_failed_login_hotspot and rt.failed_login_info then
            send_message = true
            headline = "Failed-Login Hotspot"
            log_prefix = "failed_login_"
        end

        -- filter_geoippolicyd
        if rt.filter_geoippolicyd then
            send_message = true
            headline = "GeoIP-Policyd"
            log_prefix = "geoippolicyd_"
        end

        -- action_haveibeenpwnd
        if rt.action_haveibeenpwnd then
            send_message = true
            headline = "Password leaked"
            log_preifx = "haveibeenpwnd_"
        end

        -- feature_global_pattern
        if rt.feature_global_pattern then
            send_message = true
            headline = "Global Pattern Update"
            log_prefix = "global_pattern_"
        end

        -- account protection mode
        if rt.filter_account_protection_mode or (rt.account_protection and rt.account_protection.active) then
            send_message = true
            headline = "Account Protection"
            log_prefix = "acct_protection_"
        end

        -- dynamic response
        if rt.dynamic_response then
            send_message = true
            headline = "Dynamic Response"
            log_prefix = "dynamic_response_"
        end
    end

    local pwnd = nauthilus_context.context_get("haveibeenpwnd_hash_info")
    if pwnd then
        pwnd_info = pwnd
    end

    -- Only send if authentication failed AND account is set
    if send_message and (not request.authenticated) and request.account and request.account ~= "" then
        local client = http.client()
        local bot = telegram.bot(TELEGRAM_PASSWORD, client)

        ts = nauthilus_util.get_current_timestamp()
        if ts == nil then
            ts = "unknown"
        end

        local proto = request.protocol
        if proto == "" then
            proto = "n/a"
        end

        local username = request.username
        if username == "" then
            username = "n/a"
        end

        local account = request.account
        if account == "" then
            -- this branch shouldn't happen due to the gate, but keep fallback for safety
            account = "n/a"
        end

        -- Compute password hash if password is present
        if request.password and request.password ~= "" then
            password_hash = nauthilus_password.generate_password_hash(request.password)
        end

        local unique_user_id = request.unique_user_id
        if unique_user_id == "" then
            unique_user_id = "n/a"
        end

        local display_name = request.display_name
        if display_name == "" then
            display_name = "n/a"
        end

        local hostname = request.client_hostname
        if hostname == "" then
            hostname = "n/a"
        end

        local mustache, err = template.choose("mustache")
        nauthilus_util.if_error_raise(err)

        -- Failed-login hotspot details if present
        local failed_login_count = "n/a"
        local failed_login_rank = "n/a"
        local failed_login_recognized = "n/a"
        if rt and rt.failed_login_info then
            if rt.failed_login_info.new_count ~= nil then
                failed_login_count = tostring(rt.failed_login_info.new_count)
            end
            if rt.failed_login_info.rank ~= nil then
                failed_login_rank = tostring(rt.failed_login_info.rank)
            end
            if rt.failed_login_info.recognized_account ~= nil then
                failed_login_recognized = tostring(rt.failed_login_info.recognized_account)
            end
        end

        -- GeoIP details if present
        local geoip_guid = "n/a"
        local geoip_country = "n/a"
        local geoip_iso_codes = "n/a"
        local geoip_status = "n/a"
        if rt and rt.geoip_info then
            if rt.geoip_info.guid and rt.geoip_info.guid ~= "" then
                geoip_guid = rt.geoip_info.guid
            end
            if rt.geoip_info.current_country_code and rt.geoip_info.current_country_code ~= "" then
                geoip_country = rt.geoip_info.current_country_code
            end
            if rt.geoip_info.status and rt.geoip_info.status ~= "" then
                geoip_status = rt.geoip_info.status
            end
            if rt.geoip_info.iso_codes_seen and type(rt.geoip_info.iso_codes_seen) == "table" then
                local parts = {}
                for _, v in ipairs(rt.geoip_info.iso_codes_seen) do
                    table.insert(parts, tostring(v))
                end
                if #parts > 0 then
                    geoip_iso_codes = table.concat(parts, ",")
                end
            end
        end

        -- Global pattern details if present
        local gp_attempts = "n/a"
        local gp_unique_ips = "n/a"
        local gp_unique_users = "n/a"
        local gp_ips_per_user = "n/a"
        if rt and rt.global_pattern_info then
            local gpi = rt.global_pattern_info
            if gpi.attempts ~= nil then gp_attempts = tostring(gpi.attempts) end
            if gpi.unique_ips ~= nil then gp_unique_ips = tostring(gpi.unique_ips) end
            if gpi.unique_users ~= nil then gp_unique_users = tostring(gpi.unique_users) end
            if gpi.ips_per_user ~= nil then gp_ips_per_user = tostring(gpi.ips_per_user) end
        end

        -- Account protection details if present
        local prot_active = "false"
        local prot_reason = "n/a"
        local prot_backoff = "n/a"
        local prot_delay_ms = "n/a"
        if rt and rt.account_protection then
            prot_active = tostring(rt.account_protection.active)
            if rt.account_protection.reason ~= nil then prot_reason = tostring(rt.account_protection.reason) end
            if rt.account_protection.backoff_level ~= nil then prot_backoff = tostring(rt.account_protection.backoff_level) end
            if rt.account_protection.delay_ms ~= nil then prot_delay_ms = tostring(rt.account_protection.delay_ms) end
        end

        -- Dynamic response details if present
        local dyn_threat = "n/a"
        local dyn_response = "n/a"
        if rt and rt.dynamic_response then
            if rt.dynamic_response.threat_level ~= nil then dyn_threat = tostring(rt.dynamic_response.threat_level) end
            if rt.dynamic_response.response ~= nil then dyn_response = tostring(rt.dynamic_response.response) end
        end

        -- Template data
        local values = {}
        values.session = request.session
        values.ts = ts
        values.client_ip = request.client_ip
        values.hostname = hostname
        values.proto = proto
        values.display_name = display_name
        values.account = account
        values.unique_user_id = unique_user_id
        values.username = username
        values.pwnd_info = pwnd_info
        values.brute_force_bucket = brute_force_bucket
        values.password_hash = password_hash
        values.failed_login_count = failed_login_count
        values.failed_login_rank = failed_login_rank
        values.failed_login_recognized = failed_login_recognized
        values.geoip_guid = geoip_guid
        values.geoip_country = geoip_country
        values.geoip_iso_codes = geoip_iso_codes
        values.geoip_status = geoip_status
        values.gp_attempts = gp_attempts
        values.gp_unique_ips = gp_unique_ips
        values.gp_unique_users = gp_unique_users
        values.gp_ips_per_user = gp_ips_per_user
        values.prot_active = prot_active
        values.prot_reason = prot_reason
        values.prot_backoff = prot_backoff
        values.prot_delay_ms = prot_delay_ms
        values.dyn_threat = dyn_threat
        values.dyn_response = dyn_response

        nauthilus_prometheus.increment_gauge(HCCR, { service = N })

        local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { bot = "send" })
        local _, err_bat = bot:sendMessage({
            chat_id = TELEGRAM_CHAT_ID,
            text = headline .. mustache:render(":\n\nSESSION {{session}}\nTS {{ts}}\nIP {{client_ip}}\nHOSTNAME {{hostname}}\nPROTOCOL {{proto}}\nDISPLAY_NAME {{display_name}}\nACCOUNT {{account}}\nUNIQUE ID {{unique_user_id}}\nUSERNAME {{username}}\nPASSWORD HASH {{password_hash}}\nPWND INFO {{pwnd_info}}\nBRUTE FORCE BUCKET {{brute_force_bucket}}\nFAILED LOGIN COUNT {{failed_login_count}}\nFAILED LOGIN RANK {{failed_login_rank}}\nFAILED LOGIN RECOGNIZED {{failed_login_recognized}}\nGEOIP GUID {{geoip_guid}}\nGEOIP COUNTRY {{geoip_country}}\nGEOIP ISO CODES {{geoip_iso_codes}}\nGEOIP STATUS {{geoip_status}}\nGLOBAL ATTEMPTS {{gp_attempts}}\nGLOBAL UNIQUE IPs {{gp_unique_ips}}\nGLOBAL UNIQUE USERS {{gp_unique_users}}\nGLOBAL IPs/USER {{gp_ips_per_user}}\nACCT PROTECTION ACTIVE {{prot_active}}\nACCT PROTECTION REASON {{prot_reason}}\nACCT BACKOFF LEVEL {{prot_backoff}}\nACCT DELAY MS {{prot_delay_ms}}\nDYN THREAT {{dyn_threat}}\nDYN RESPONSE {{dyn_response}}", values)
        })
        nauthilus_prometheus.stop_timer(timer)
        nauthilus_prometheus.decrement_gauge(HCCR, { service = N })
        nauthilus_util.if_error_raise(err_bat)
    end

    rt.post_telegram = true
    nauthilus_context.context_set("rt", rt)

    return nauthilus_builtin.ACTION_RESULT_OK
end
