local json = require("json")

function nauthilus_call_feature(request)
    request.password = nil
    request.caller = "demo.lua"
    request.level = "info"

    local result, err = json.encode(request)
    if err then
        error(err)
        nauthilus.context_set("feature_demo", "fail")

        return nauthilus.FEATURE_TRIGGER_NO, nauthilus.FEATURES_ABORT_NO, nauthilus.FEATURE_RESULT_FAIL
    end

    print(result)

    nauthilus.context_set("silly_dog", "Wuff!")

    -- Example on how to track the result of features, ... with a result table (rt)
    local rt = nauthilus.context_get("rt")
    if rt == nil then
        rt = {}
    end

    rt.feature_demo = true

    nauthilus.context_set("rt", rt)

    nauthilus.context_set("feature_demo", "ok")
    nauthilus.custom_log_add("feature_demo", "success")

    return nauthilus.FEATURE_TRIGGER_NO, nauthilus.FEATURES_ABORT_NO, nauthilus.FEATURE_RESULT_OK
end
