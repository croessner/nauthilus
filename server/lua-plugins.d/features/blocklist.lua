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

local N = "feature_blocklist"

function nauthilus_call_feature(request)
    if not request.client_ip then
        nauthilus_builtin.custom_log_add(N, "no client IP found")

        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_FAILURE
    end

    -- Get result table
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then
        rt = {}
    end

    local t = {}

    t.ip = request.client_ip

    local payload, json_encode_err = json.encode(t)
    nauthilus_util.if_error_raise(json_encode_err)

    local blocklist_request = http.request("POST", os.getenv("BLOCKLIST_URL"), payload)
    blocklist_request:header_set("Content-Type", "application/json")

    local result, request_err = client:do_request(blocklist_request)
    nauthilus_util.if_error_raise(request_err)

    if result.code ~= 200 then
        nauthilus_util.if_error_raise(N .. "_status_code=" .. tostring(result.code))
    end

    local response, err_jdec = json.decode(result.body)
    nauthilus_util.if_error_raise(err_jdec)

    if response.error then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_FAILURE
    end

    if response.found then
        if nauthilus_util.is_table(rt) then
            rt.feature_blocklist = true

            nauthilus_context.context_set("rt", rt)
        end

        nauthilus_builtin.custom_log_add(N .. "_ip", request.client_ip)
        nauthilus_builtin.status_message_set("IP address blocked")

        return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_YES, nauthilus_builtin.FEATURE_RESULT_OK
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
