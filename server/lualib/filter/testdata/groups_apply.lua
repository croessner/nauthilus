function nauthilus_call_filter(request)
    local backend_result = nauthilus_backend_result.new()
    backend_result:groups({"Developer", "Ops"})
    backend_result:group_dns({"cn=Developer,ou=groups,dc=example,dc=org"})
    nauthilus_backend.apply_backend_result(backend_result)

    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
