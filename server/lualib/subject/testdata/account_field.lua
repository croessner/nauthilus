function nauthilus_call_subject(request)
    local backend_result = nauthilus_backend_result.new()
    local attrs = {}
    attrs["Account-Field"] = request.account_field or ""
    backend_result:attributes(attrs)
    nauthilus_backend.apply_backend_result(backend_result)
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
