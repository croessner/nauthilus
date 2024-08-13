local nauthilus_util = require("nauthilus_util")

local http = require("http")
local telegram = require("telegram")
local json = require("json")
local template = require("template")

local client = http.client()
local bot = telegram.bot(os.getenv("TELEGRAM_PASSWORD"), client)

local N = "telegram"

function nauthilus_call_action(request)
    local send_message = false
    local pwnd_info = "n/a"
    local headline = "Information"
    local log_prefix = ""
    local ts

    -- Get result table
    local rt = nauthilus.context_get("rt")
    if rt == nil then
        rt = {}
    end

    ts = nauthilus_util.get_current_timestamp()
    if ts == nil then
        ts = "unknown"
    end

    if nauthilus_util.is_table(rt) and nauthilus_util.table_length(rt) > 0 then
        if request.debug then
            rt.caller = "telegram.lua"

            local rt_json, err = json.encode(rt)
            nauthilus_util.raise_error(err)

            if request.debug then
                print(rt_json)
            end

            rt.caller = nil
        end

        -- brute_force_haproxy
        if rt.brute_force_haproxy then
            send_message = true
            headline = "Brute force"
            log_prefix = "brute_force_"
        end

        -- feature_haproxy (not part of demo plugins)
        if rt.feature_haproxy then
            send_message = true
            if request.feature ~= nil and request.feature ~= "" then
                headline = "Feature " .. request.feature .. " triggered"
                log_prefix = request.feature .. "_"
            else
                headline = "Feature triggered"
                log_prefix = "feature_"
            end
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

    local pwnd = nauthilus.context_get("haveibeenpwnd_hash_info")
    if pwnd then
        pwnd_info = pwnd
    end

    if send_message then
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
        nauthilus_util.raise_error(err)

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

        local _, err_bat = bot:sendMessage({
            chat_id = tonumber(os.getenv("TELEGRAM_CHAT_ID")),
            text = headline .. mustache:render(":\n\nSESSION {{session}}\nTS {{ts}}\nIP {{client_ip}}\nHOSTNAME {{hostname}}\nPROTOCOL {{proto}}\nDISPLAY_NAME {{display_name}}\nACCOUNT {{account}}\nUNIQUE ID {{unique_user_id}}\nUSERNAME {{username}}\nPWND INFO {{pwnd_info}}", values)
        })
        nauthilus_util.raise_error(err_bat)

        result.caller = N .. ".lua"
        result.action_class = "post"
        result.password = nil

        if request.log_level == "debug" or request.log_level == "info" then
            if request.log_format == "json" then
                local result_json, err_enc = json.encode(result)
                nauthilus_util.raise_error(err_enc)

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
    nauthilus.context_set("rt", rt)

    nauthilus.context_set("action_telegram", "ok")
    nauthilus.custom_log_add("action_" .. log_prefix .. "telegram", "success")

    return nauthilus.ACTION_RESULT_OK
end
