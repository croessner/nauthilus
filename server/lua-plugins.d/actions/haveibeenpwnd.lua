local nauthilus_util = require("nauthilus_util")

local http = require("http")
local crypto = require('crypto')
local strings = require("strings")
local template = require("template")

local client = http.client({
    timeout = 30,
    user_agent = "Nauthilus",
})

local smtp_message = [[
Hello,

a password was found on haveibeenpwnd!

Account: {{account}}
Hash: {{hash}}
Count: {{count}}

Please inform the user about this incident and lock the account.

Regards

Postmaster
]]

---@param request table
---@return number
function nauthilus_call_action(request)
    if not request.no_auth and request.authenticated then
        local redis_key = "ntc:HAVEIBEENPWND:" .. crypto.md5(request.account)
        local hash = string.lower(crypto.sha1(request.password))

        local redis_hash_count, err_redis_hget = nauthilus.redis_hget(redis_key, hash:sub(1, 5), "number")
        nauthilus_util.if_error_raise(err_redis_hget)

        if redis_hash_count then
            if nauthilus_util.is_number(redis_hash_count) then
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
        nauthilus_util.if_error_raise(err)

        if result.code ~= 200 then
            error("haveibeenpwnd did not return status code 200")
        end

        for line in result.body:gmatch("([^\n]*)\n?") do
            local cmp_hash = strings.split(line, ":")
            if #cmp_hash == 2 and string.lower(cmp_hash[1]) == hash then
                nauthilus.redis_hset(redis_key, hash:sub(1, 5), cmp_hash[2])
                nauthilus.redis_expire(redis_key, 3600)

                -- Required by telegram.lua
                nauthilus.context_set("haveibeenpwnd_hash_info", hash:sub(1, 5) .. cmp_hash[2])
                nauthilus.custom_log_add("action_haveibeenpwnd", "leaked")

                ---@type string found
                ---@type string err_redis_hget2
                local already_sent_mail, err_redis_hget2 = nauthilus.redis_hget(redis_key, "send_mail")
                nauthilus_util.if_error_raise(err_redis_hget2)

                if already_sent_mail == "" then
                    local smtp_use_lmtp = os.environ("SMTP_USE_LMTP")
                    local smtp_server = os.environ("SMTP_SERVER")
                    local smtp_port = os.environ("SMTP_PORT")
                    local smtp_helo_name = os.environ("SMTP_HELO_NAME")
                    local smtp_tls = os.environ("SMTP_TLS")
                    local smtp_starttls = os.environ("SMTP_STARTTLS")
                    local smtp_username = os.environ("SMTP_USERNAME")
                    local smtp_password = os.environ("SMTP_PASSWORD")
                    local smtp_mail_from = os.environ("SMTP_MAIL_FROM")
                    local smtp_rcpt_to = os.environ("SMTP_RCPT_TO")

                    local mustache, err_tmpl = template.choose("mustache")
                    nauthilus_util.if_error_raise(err_tmpl)

                    local tmpl_data = {
                        account = request.account,
                        hash = hash:sub(1, 5),
                        count = cmp_hash[2],
                    }

                    local err_smtp = nauthilus.send_mail({
                        lmtp = smtp_use_lmtp,
                        server = smtp_server,
                        port = tonumber(smtp_port),
                        helo_name = smtp_helo_name,
                        username = smtp_username,
                        password = smtp_password,
                        tls = nauthilus_util.toboolean(smtp_tls),
                        smtp_starttls = nauthilus_util.toboolean(smtp_starttls),
                        from = smtp_mail_from,
                        to = { smtp_rcpt_to },
                        subject = "Password leak detected for account " .. request.account,
                        body = mustache:render(smtp_message, tmpl_data)
                    })
                    nauthilus_util.if_error_raise(err_smtp)

                    nauthilus.redis_hset(redis_key, "send_mail", 1)
                    nauthilus.redis_expire(redis_key, 86400)
                end

                return nauthilus.ACTION_RESULT_OK
            end
        end

        nauthilus.redis_hset(redis_key, hash:sub(1, 5), 0)
        nauthilus.redis_expire(redis_key, 86400)
    end

    nauthilus.custom_log_add("action_haveibeenpwnd", "success")

    return nauthilus.ACTION_RESULT_OK
end
