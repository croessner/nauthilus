function nauthilus_call_feature(request)
    local demo = nauthilus.context_get("feature_demo")
    if demo ~= nil and demo == "ok" then
        print("Adding state to comm")

        local fn = nauthilus.context_get("fn")
        if fn ~= nil then
            fn()
        end

        local fn2 = nauthilus.context_get("fn2")
        if fn2 ~= nil then
            fn2()
        end

        nauthilus.context_set("feature_comm", "ok")
        nauthilus.custom_log_add("feature_comm", "success")

        return nauthilus.FEATURE_TRIGGER_NO, nauthilus.FEATURES_ABORT_NO, nauthilus.FEATURE_RESULT_OK
    else
        return nauthilus.FEATURE_TRIGGER_NO, nauthilus.FEATURES_ABORT_NO, nauthilus.FEATURE_RESULT_FAIL
    end
end
