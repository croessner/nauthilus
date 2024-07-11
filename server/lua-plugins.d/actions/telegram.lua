local http = require("http")
local telegram = require("telegram")
local json = require("json")
local time = require("time")
local template = require("template")

local client = http.client()
local bot = telegram.bot(os.getenv("TELEGRAM_PASSWORD"), client)

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

    -- Handle errors
    local function error_str(err)
        local m = {}

        m.caller = "telegram.lua"
        m.ts = ts
        m.error = err

        local m_json, err = json(m)
        if err then
            return err
        end

        return m_json
    end

    -- Create time stamp string
    local function get_current_ts()
        local result, err = time.format(time.unix(), "2006-01-02T15:04:05 -07:00", "Europe/Berlin")
        if err then
            error(error_str(err))

            return nil
        end

        return result
    end

    ts = get_current_ts()
    if ts == nil then
        ts = "unknown"
    end

    -- Count table elements
    local function table_length(t)
        local count = 0

        for _ in pairs(t) do
            count = count + 1
        end

        return count
    end

    if type(rt) == "table" and table_length(rt) > 0 then
        if request.debug then
            rt.caller = "telegram.lua"

            local rt_json, err = json.encode(rt)
            if err then
                error(error_str(err))

                return nauthilus.ACTION_RESULT_FAIL
            end

            print(rt_json)
            rt.caller = nil
        end

        if rt.feature_demo ~= nil then
            send_message = false -- Do not send demo messages!
            headline = "Demo"
            log_prefix = "demo_"
        end

        -- brute_force_haproxy
        if rt.brute_force_haproxy ~= nil and rt.brute_force_haproxy then
            send_message = true
            headline = "Brute force"
            log_prefix = "brute_force_"
        end

        -- feature_haproxy
        if rt.feature_haproxy ~= nil and rt.feature_haproxy then
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
        if rt.filter_geoippolicyd ~= nil and rt.filter_geoippolicyd then
            send_message = true
            headline = "GeoIP-Policyd"
            log_prefix = "geoippolicyd_"
        end

        -- action_haveibeenpwnd
        if rt.action_haveibeenpwnd ~= nil and rt.action_haveibeenpwnd then
            send_message = true
            headline = "Password leaked"
            log_preifx = "haveibeenpwnd_"
        end
    end

    local pwnd = nauthilus.context_get("haveibeenpwnd_hash_info")

    local rbl = nauthilus.context_get("rbl_haproxy")
    if rbl ~= nil and rbl == "ok" then
        -- We do not want lots of RBL messages
        send_message = false
    end

    if pwnd ~= nil then
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
        if err then
            error(error_str(err))

            return nauthilus.ACTION_RESULT_FAIL
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

        local _, err = bot:sendMessage({
            chat_id = tonumber(os.getenv("TELEGRAM_CHAT_ID")),
            text = headline .. mustache:render(":\n\nSESSION {{session}}\nTS {{ts}}\nIP {{client_ip}}\nHOSTNAME {{hostname}}\nPROTOCOL {{proto}}\nDISPLAY_NAME {{display_name}}\nACCOUNT {{account}}\nUNIQUE ID {{unique_user_id}}\nUSERNAME {{username}}\nPWND INFO {{pwnd_info}}", values)
        })

        if err then
            error(error_str(err))

            return nauthilus.ACTION_RESULT_FAIL
        end

        result.caller = "telegram.lua"
        result.action_class = "post"
        result.password = nil

        local result_json, err = json.encode(result)
        if err then
            error(error_str(err))

            return nauthilus.ACTION_RESULT_FAIL
        end

        print(result_json)
    end

    rt.post_telegram = true
    nauthilus.context_set("rt", rt)

    nauthilus.context_set("action_telegram", "ok")
    nauthilus.custom_log_add("action_" .. log_prefix .. "telegram", "success")

    return nauthilus.ACTION_RESULT_OK
end
