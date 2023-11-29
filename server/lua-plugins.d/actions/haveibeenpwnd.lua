local http = require("http")
local crypto = require('crypto')
local strings = require("strings")

local client = http.client({
    timeout = 30,
    user_agent = "Nauthilus/2.5pre",
})

function nauthilus_call_action(request)
    if not request.no_auth and request.authenticated then
        local hash = crypto.sha1(request.password)

        local http_request = http.request("GET", "https://api.pwnedpasswords.com/range/" .. hash:sub(1, 5), "")

        local result, err = client:do_request(http_request)
        if err then
            error("{\"caller\":\"haveibeenpwnd.lua\",\"error\":\"" .. err .. "\"")

            return nauthilus.ACTION_RESULT_FAIL
        end
        if not (result.code == 200) then
            error("{\"caller\":\"haveibeenpwnd.lua\",\"error\":\"haveibeenpwnd did not return status code 200\"")

            return nauthilus.ACTION_RESULT_FAIL
        end

        for line in result.body:gmatch("([^\n]*)\n?") do
            local cmp_hash, count = strings.split(line, ":")
            if cmp_hash == hash then
                local rt = nauthilus.context_get("rt")
                if rt == nil then
                    rt = {}
                end
                if type(rt) == table then
                    rt.action_haveibeenpwnd = true
                end

                nauthilus.context_set("rt", rt)

                nauthilus.context_set("haveibeenpwnd_hash_info", hash:sub(1,5) .. count)
                nauthilus.context_set("action_haveibeenpwnd", "ok")
                nauthilus.custom_log_add("action_haveibeenpwnd", "leaked")

                return nauthilus.ACTION_RESULT_OK
            end
        end
    end

    nauthilus.context_set("action_haveibeenpwnd", "ok")
    nauthilus.custom_log_add("action_haveibeenpwnd", "success")

    return nauthilus.ACTION_RESULT_OK
end
