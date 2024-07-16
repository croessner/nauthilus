local http = require("http")
local crypto = require('crypto')
local strings = require("strings")

local client = http.client({
    timeout = 30,
    user_agent = "Nauthilus",
})

function nauthilus_call_action(request)
    if not request.no_auth and request.authenticated then
        local redis_key = "ntc:HAVEIBEENPWND:" .. crypto.md5(request.account)
        local hash = string.lower(crypto.sha1(request.password))

        local redis_hash_count, err_redis_hget = nauthilus.redis_hget(redis_key, hash:sub(1, 5), "number")
        if err_redis_hget then
            error(err_redis_hget)
        end

        if redis_hash_count ~= nil then
            if type(redis_hash_count) == "number" then
                if redis_hash_count > 0 then
                    -- Required by telegram.lua
                    nauthilus.context_set("haveibeenpwnd_hash_info", hash:sub(1, 5) .. redis_hash_count)

                    nauthilus.custom_log_add("action_haveibeenpwnd", "leaked")

                    return nauthilus.ACTION_RESULT_OK
                else
                    nauthilus.custom_log_add("action_haveibeenpwnd", "success")

                    return nauthilus.ACTION_RESULT_OK
                end
            end
        end

        local http_request = http.request("GET", "https://api.pwnedpasswords.com/range/" .. hash:sub(1, 5), "")

        local result, err = client:do_request(http_request)
        if err then
            error(err)
        end
        if not (result.code == 200) then
            error("haveibeenpwnd did not return status code 200")
        end

        for line in result.body:gmatch("([^\n]*)\n?") do
            local cmp_hash  = strings.split(line, ":")
            if #cmp_hash == 2 and string.lower(cmp_hash[1]) == hash then
                nauthilus.redis_hset(redis_key, hash:sub(1, 5), cmp_hash[2])
                nauthilus.redis_expire(redis_key, 3600)

                -- Required by telegram.lua
                nauthilus.context_set("haveibeenpwnd_hash_info", hash:sub(1, 5) .. cmp_hash[2])

                nauthilus.custom_log_add("action_haveibeenpwnd", "leaked")

                return nauthilus.ACTION_RESULT_OK
            end
        end

        nauthilus.redis_hset(redis_key, hash:sub(1, 5), 0)
        nauthilus.redis_expire(redis_key, 86400)
    end

    nauthilus.custom_log_add("action_haveibeenpwnd", "success")

    return nauthilus.ACTION_RESULT_OK
end
