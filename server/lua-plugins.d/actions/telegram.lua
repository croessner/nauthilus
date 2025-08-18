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

local HCCR = "http_client_concurrent_requests_total"

function nauthilus_call_action(request)
    if request.no_auth then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Go-backed password module
    dynamic_loader("nauthilus_password")
    local nauthilus_password = require("nauthilus_password")

    dynamic_loader("nauthilus_context")
    local nauthilus_context = require("nauthilus_context")

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
    end

    local pwnd = nauthilus_context.context_get("haveibeenpwnd_hash_info")
    if pwnd then
        pwnd_info = pwnd
    end

    -- Only send if request.account is set
    if send_message and request.account and request.account ~= "" then
        dynamic_loader("nauthilus_prometheus")
        local nauthilus_prometheus = require("nauthilus_prometheus")

        dynamic_loader("nauthilus_gll_http")
        local http = require("http")

        dynamic_loader("nauthilus_gll_telegram")
        local telegram = require("telegram")

        dynamic_loader("nauthilus_gll_template")
        local template = require("template")

        local client = http.client()
        local bot = telegram.bot(os.getenv("TELEGRAM_PASSWORD"), client)

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
        if rt and rt.failed_login_info then
            if rt.failed_login_info.new_count ~= nil then
                failed_login_count = tostring(rt.failed_login_info.new_count)
            end
            if rt.failed_login_info.rank ~= nil then
                failed_login_rank = tostring(rt.failed_login_info.rank)
            end
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

        nauthilus_prometheus.increment_gauge(HCCR, { service = N })

        local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { bot = "send" })
        local _, err_bat = bot:sendMessage({
            chat_id = tonumber(os.getenv("TELEGRAM_CHAT_ID")),
            text = headline .. mustache:render(":\n\nSESSION {{session}}\nTS {{ts}}\nIP {{client_ip}}\nHOSTNAME {{hostname}}\nPROTOCOL {{proto}}\nDISPLAY_NAME {{display_name}}\nACCOUNT {{account}}\nUNIQUE ID {{unique_user_id}}\nUSERNAME {{username}}\nPASSWORD HASH {{password_hash}}\nPWND INFO {{pwnd_info}}\nBRUTE FORCE BUCKET {{brute_force_bucket}}\nFAILED LOGIN COUNT {{failed_login_count}}\nFAILED LOGIN RANK {{failed_login_rank}}", values)
        })
        nauthilus_prometheus.stop_timer(timer)
        nauthilus_prometheus.decrement_gauge(HCCR, { service = N })
        nauthilus_util.if_error_raise(err_bat)
    end

    rt.post_telegram = true
    nauthilus_context.context_set("rt", rt)

    return nauthilus_builtin.ACTION_RESULT_OK
end
