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

    dynamic_loader("nauthilus_context")
    local nauthilus_context = require("nauthilus_context")

    local send_message = false
    local pwnd_info = "n/a"
    local headline = "Information"
    local log_prefix = ""
    local brute_force_bucket = "n/a"
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

    if send_message then
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
            account = "n/a"
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

        nauthilus_prometheus.increment_gauge(HCCR, { service = N })

        local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { bot = "send" })
        local _, err_bat = bot:sendMessage({
            chat_id = tonumber(os.getenv("TELEGRAM_CHAT_ID")),
            text = headline .. mustache:render(":\n\nSESSION {{session}}\nTS {{ts}}\nIP {{client_ip}}\nHOSTNAME {{hostname}}\nPROTOCOL {{proto}}\nDISPLAY_NAME {{display_name}}\nACCOUNT {{account}}\nUNIQUE ID {{unique_user_id}}\nUSERNAME {{username}}\nPWND INFO {{pwnd_info}}\nBRUTE FORCE BUCKET {{brute_force_bucket}}", values)
        })
        nauthilus_prometheus.stop_timer(timer)
        nauthilus_prometheus.decrement_gauge(HCCR, { service = N })
        nauthilus_util.if_error_raise(err_bat)
    end

    rt.post_telegram = true
    nauthilus_context.context_set("rt", rt)

    return nauthilus_builtin.ACTION_RESULT_OK
end
