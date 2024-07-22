local http = require("http")
local json = require("json")
local time = require("time")

local client = http.client({
    timeout = 30,
    user_agent = "Nauthilus"
})

local N = "filter_geoippolicyd"

function nauthilus_call_filter(request)
    local ts
    local function get_current_ts()
        local result, err = time.format(time.unix(), "2006-01-02T15:04:05 -07:00", "Europe/Berlin")
        if err then
            error(err)
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

                    nauthilus.custom_log_add(N .. "_" .. item, log_str)
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

    ts = get_current_ts()
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
        if json_encode_err then
            error(json_encode_err)
        end

        local geoip_request = http.request("POST", os.getenv("GEOIP_POLICY_URL"), payload)
        geoip_request:header_set("Content-Type", "application/json")

        local result, request_err = client:do_request(geoip_request)
        if request_err then
            error(request_err)
        end
        if not (result.code == 202) then
            error(request_err)
        end

        if request.debug then
            print(result.body)
        end

        local response, json_decode_err = json.decode(result.body)
        if json_decode_err then
            error(json_decode_err)
        end

        if response.err == nil then
            nauthilus.custom_log_add(N .. "_guid", response.guid)

            if response.object ~= nil then
                add_custom_logs(response.object)

                -- Try to get all ISO country codes
                if type(response.object) == "table" then
                    local result_iso_codes = {}

                    for key, values in pairs(response.object) do
                        if key == "foreign_countries_seen" or key == "home_countries_seen" then
                            if type(values) == "table" then
                                for _, iso_code in ipairs(values) do
                                    if not exists_in_table(result_iso_codes, iso_code) then
                                        table.insert(result_iso_codes, iso_code)
                                    end
                                end
                            end
                        end
                    end

                    nauthilus.context_set(N .. "_iso_codes_seen", result_iso_codes)
                end
            end

            if not response.result then
                nauthilus.context_set(N, "ok")
                nauthilus.custom_log_add(N, "blocked")

                return nauthilus.FILTER_REJECT, nauthilus.FILTER_RESULT_OK
            end
        else
            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        end

        nauthilus.context_set(N, "ok")
        nauthilus.custom_log_add(N, "success")
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
