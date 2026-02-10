function nauthilus_call_filter(request)
    local backend_result = nauthilus_backend_result.new()
    local attrs = {}
    attrs["Account-Field"] = request.account_field or ""
    backend_result:attributes(attrs)
    nauthilus_backend.apply_backend_result(backend_result)
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
