local http = require("http")
local json = require("json")
local time = require("time")

local client = http.client({
    timeout = 30,
    user_agent = "Nauthilus"
})

function nauthilus_call_filter(request)
	local ts
    local fg = "filter_geoippolicyd"

    local function error_str(err)
        local m = {}

        m.caller = "geoip.lua"
        m.ts = ts
        m.error = err

        local m_json, json_encode_err = json.encode(m)
        if json_encode_err then
            return json_encode_err
        end

        return m_json
    end

    local function get_current_ts()
        local result, err = time.format(time.unix(), "2006-01-02T15:04:05 -07:00", "Europe/Berlin")
        if err then
            error(error_str(err))

            return nil
        end

        return result
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

                    nauthilus.custom_log_add(fg .. "_" .. item, log_str)
                end
            end
        end
    end

    ts = get_current_ts()
    if ts == nil then
        ts = "unknown"
    end

    if request.user_found and request.authenticated and not request.no_auth then
        local t = {}

        t.key = "client"
        t.value = {
            address = request.client_ip,
            sender = request.account
        }

        local payload, json_encode_err = json.encode(t)
        if json_encode_err then
            error(error_str(json_encode_err))

            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        end

        local geoip_request = http.request("POST", os.getenv("GEOIP_POLICY_URL"), payload)
        geoip_request:header_set("Content-Type", "application/json")

        local result, request_err = client:do_request(geoip_request)
        if request_err then
            error(error_str(request_err))

            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        end
        if not (result.code == 202) then
            error(error_str(request_err))

            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        end

        print(result.body)
        local response, json_decode_err = json.decode(result.body)
        if json_decode_err then
            error(error_str(json_decode_err))

            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        end

        if response.err == nil then
            nauthilus.custom_log_add(fg .. "_guid", response.guid)

            if response.object ~= nil then
                add_custom_logs(response.object)
            end

            if not response.result then
                -- The request should be rejected
                local rt = nauthilus.context_get("rt")
                if rt == nil then
                    rt = {}
                end
                if type(rt) == "table" then
                    rt.filter_geoip = true
                end

                nauthilus.context_set("rt", rt)

                nauthilus.context_set(fg, "ok")
                nauthilus.custom_log_add(fg, "blocked")

                return nauthilus.FILTER_REJECT, nauthilus.FILTER_RESULT_OK
            end
        else
            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        end

        nauthilus.context_set(fg, "ok")
        nauthilus.custom_log_add(fg, "success")
	else
        -- We must restore a failed authentication flag!
        if not request.authenticated then
            return nauthilus.FILTER_REJECT, nauthilus.FILTER_RESULT_OK
        end
    end

    -- The request should be accepted
    return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_OK
end

-- vim: ts=4 sw=4 expandtab
