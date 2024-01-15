function nauthilus_call_feature(request)
    local demo = nauthilus.context_get("feature_demo")
    if demo ~= nil and demo == "ok" then
        print("Adding state to comm")

        nauthilus.context_set("feature_comm", "ok")
        nauthilus.custom_log_add("feature_comm", "success")

        return nauthilus.FEATURE_TRIGGER_NO, nauthilus.FEATURES_ABORT_NO, nauthilus.FEATURE_RESULT_OK
    else
        return nauthilus.FEATURE_TRIGGER_NO, nauthilus.FEATURES_ABORT_NO, nauthilus.FEATURE_RESULT_FAIL
    end
end
