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
    local ts

    -- Get result table
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then
        rt = {}
    end

    ts = nauthilus_util.get_current_timestamp()
    if ts == nil then
        ts = "unknown"
    end

    if nauthilus_util.is_table(rt) and nauthilus_util.table_length(rt) > 0 then
        -- brute_force_haproxy
        if rt.brute_force_haproxy then
            send_message = true
            headline = "Brute force"
            log_prefix = "brute_force_"
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

        dynamic_loader("nauthilus_gll_json")
        local json = require("json")

        local client = http.client()
        local bot = telegram.bot(os.getenv("TELEGRAM_PASSWORD"), client)

        local result = request

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

        nauthilus_prometheus.create_summary_vec(N .. "_duration_seconds", "HTTP request to the telegram network", {"bot"})

        local timer = nauthilus_prometheus.start_timer(N .. "_duration_seconds", {bot="send"})
        local _, err_bat = bot:sendMessage({
            chat_id = tonumber(os.getenv("TELEGRAM_CHAT_ID")),
            text = headline .. mustache:render(":\n\nSESSION {{session}}\nTS {{ts}}\nIP {{client_ip}}\nHOSTNAME {{hostname}}\nPROTOCOL {{proto}}\nDISPLAY_NAME {{display_name}}\nACCOUNT {{account}}\nUNIQUE ID {{unique_user_id}}\nUSERNAME {{username}}\nPWND INFO {{pwnd_info}}", values)
        })
        nauthilus_prometheus.stop_timer(timer)
        nauthilus_util.if_error_raise(err_bat)

        result.caller = N .. ".lua"
        result.action_class = "post"
        result.password = nil

        if request.log_level == "debug" or request.log_level == "info" then
            if request.log_format == "json" then
                local result_json, err_enc = json.encode(result)
                nauthilus_util.if_error_raise(err_enc)

                print(result_json)
            else
                local output_str = {}

                for k, v in pairs(result) do
                    if nauthilus_util.is_string(v) then
                        if string.match(v, "%s") then
                            v = '"' .. v .. '"'
                        end
                    end

                    table.insert(output_str, k .. '=' .. tostring(v))
                end

                print(table.concat(output_str, " "))
            end
        end
    end

    rt.post_telegram = true
    nauthilus_context.context_set("rt", rt)

    return nauthilus_builtin.ACTION_RESULT_OK
end
