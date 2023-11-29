function nauthilus_call_action(request)
    local silly_dog = nauthilus.context_get("silly_dog")

    if silly_dog ~= nil then
        print(silly_dog)
    end

    nauthilus.context_set("action_demo", "ok")
    nauthilus.custom_log_add("action_demo", "success")

    return nauthilus.ACTION_RESULT_OK
end
