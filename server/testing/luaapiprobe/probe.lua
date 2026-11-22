-- Shared host API probe for Lua environment sources, subject sources, and actions.
--
-- Every stage must expose the same Lua API as custom hooks and Lua backends. The probe fails with a
-- descriptive message for the first capability that is missing.

local probe = {}

local function expect_function(owner, owner_name, name)
    assert(type(owner) == "table", owner_name .. " is not a module table")
    assert(type(owner[name]) == "function", owner_name .. "." .. name .. " is not available")
end

local function expect_functions(owner_name, names)
    local owner = require(owner_name)

    for _, name in ipairs(names) do
        expect_function(owner, owner_name, name)
    end

    return owner
end

-- Standard libraries and base functions.
local function probe_standard_libraries()
    for _, name in ipairs({ "os", "io", "debug", "coroutine", "string", "table", "math" }) do
        assert(type(_G[name]) == "table", "standard library " .. name .. " is not available")
    end

    for _, name in ipairs({
        "print", "load", "loadstring", "dofile", "loadfile", "collectgarbage",
        "getfenv", "setfenv", "module", "newproxy", "require",
    }) do
        assert(type(_G[name]) == "function", "base function " .. name .. " is not available")
    end

    assert(os.getenv("NAUTHILUS_LUA_API_PROBE") == "set", "os.getenv does not read the process environment")
    assert(loadstring("return 7")() == 7, "loadstring does not compile chunks")

    local routine = coroutine.create(function() coroutine.yield(3) end)
    local resumed, value = coroutine.resume(routine)

    assert(resumed and value == 3, "coroutines do not run")
end

-- Bundled helper libraries, including a time zone other than UTC.
local function probe_helper_libraries()
    assert(require("strings").trim_space("  padded  ") == "padded", "strings.trim_space failed")
    expect_functions("base64", { "new_encoding" })
    expect_functions("json", { "encode", "decode" })
    expect_functions("template", { "choose" })
    expect_functions("glua_crypto", { "md5" })

    local time = expect_functions("time", { "unix", "unix_nano", "sleep", "parse", "format" })
    local formatted, err = time.format(0, "2006-01-02 15:04", "Europe/Berlin")

    assert(err == nil and formatted == "1970-01-01 01:00", "time.format rejects a non-UTC location")
end

-- Dynamic module selection must work exactly like a literal require.
local function probe_dynamic_require()
    local module_name = "nauthilus_" .. "cache"

    assert(type(require(module_name)) == "table", "dynamic require failed")
end

-- Host modules with their mutating and registering functions.
local function probe_host_modules()
    expect_functions("nauthilus_redis", {
        "register_redis_pool", "get_redis_connection",
        "redis_set", "redis_get", "redis_incr", "redis_del", "redis_rename", "redis_expire", "redis_mset",
        "redis_run_script", "redis_upload_script", "redis_pipeline",
        "redis_hset", "redis_hdel", "redis_hincrby", "redis_hincrbyfloat",
        "redis_zadd", "redis_zrem", "redis_zremrangebyscore", "redis_zremrangebyrank", "redis_zincrby",
        "redis_lpush", "redis_rpush", "redis_lpop", "redis_rpop",
        "redis_pfadd", "redis_pfmerge", "redis_sadd", "redis_srem",
    })
    expect_functions("nauthilus_prometheus", {
        "create_summary_vec", "create_counter_vec", "create_histogram_vec", "create_gauge_vec",
        "increment_counter",
    })
    expect_functions("nauthilus_brute_force", {
        "set_custom_tolerations", "set_custom_toleration", "delete_custom_toleration", "get_custom_tolerations",
    })
    expect_functions("nauthilus_psnet", { "register_connection_target", "get_connection_target" })
    expect_functions("nauthilus_misc", { "wait_random", "get_country_name", "scoped_ip" })
    expect_functions("nauthilus_mail", { "send_mail" })
    expect_functions("nauthilus_dns", { "resolve" })
    expect_functions("nauthilus_soft_whitelist", {
        "soft_whitelist_set", "soft_whitelist_get", "soft_whitelist_delete",
    })
    expect_functions("glua_http", { "get", "post", "request" })
    expect_functions("nauthilus_http_response", { "set_http_response_header", "set_http_status" })
    expect_functions("nauthilus_http_request", { "get_http_request_header", "get_all_http_request_headers" })
    expect_functions("nauthilus_context", { "context_set", "context_get", "context_delete" })
    expect_functions("nauthilus_password", {
        "compare_passwords", "check_password_policy", "generate_password_hash",
    })
    expect_functions("nauthilus_cbor", { "encode", "decode" })
    expect_functions("nauthilus_i18n", { "get_localized" })

    local cache = expect_functions("nauthilus_cache", {
        "cache_set", "cache_get", "cache_delete", "cache_update", "cache_flush", "cache_push", "cache_pop_all",
    })

    cache.cache_set("nauthilus_lua_api_probe", "written", 60)
    assert(cache.cache_get("nauthilus_lua_api_probe") == "written", "cache_set did not store the value")
    cache.cache_delete("nauthilus_lua_api_probe")
    assert(cache.cache_get("nauthilus_lua_api_probe") == nil, "cache_delete did not remove the value")
end

-- probe.run asserts the complete host API of the calling stage.
function probe.run()
    probe_standard_libraries()
    probe_helper_libraries()
    probe_dynamic_require()
    probe_host_modules()
end

-- probe.backend_selection asserts the backend-server functions of the subject stage.
function probe.backend_selection()
    expect_functions("nauthilus_backend", {
        "get_backend_servers", "select_backend_server", "get_selected_backend_server",
        "check_backend_connection", "apply_backend_result", "remove_from_backend_result",
    })
end
