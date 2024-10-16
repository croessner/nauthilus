-- Copyright (C) 2024 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

local smtp_message = [[
Hello,

your account password has been found on haveibeenpwnd! It means that your password has been leaked and is known
to the public.

Account: {{account}}
Hash: {{hash}}
Count: {{count}}

Please consider changing your password as soon as poosible. To do so, please go to the following
website: {{website}}.

Regards

Postmaster
]]

local N = "haveibeenpwnd"

local HCCR = "http_client_concurrent_requests_total"

function nauthilus_call_action(request)
    if not request.no_auth and request.authenticated then
        local nauthilus_util = require("nauthilus_util")

        dynamic_loader("nauthilus_redis")
        local nauthilus_redis = require("nauthilus_redis")

        dynamic_loader("nauthilus_mail")
        local nauthilus_mail = require("nauthilus_mail")

        dynamic_loader("nauthilus_misc")
        local nauthilus_misc = require("nauthilus_misc")

        dynamic_loader("nauthilus_context")
        local nauthilus_context = require("nauthilus_context")

        dynamic_loader("nauthilus_prometheus")
        local nauthilus_prometheus = require("nauthilus_prometheus")

        dynamic_loader("nauthilus_psnet")
        local nauthilus_psnet = require("nauthilus_psnet")

        dynamic_loader("nauthilus_gluacrypto")
        local crypto = require('crypto')

        dynamic_loader("nauthilus_gluahttp")
        local http = require("glua_http")

        dynamic_loader("nauthilus_gll_strings")
        local strings = require("strings")

        dynamic_loader("nauthilus_gll_template")
        local template = require("template")

                nauthilus_misc.wait_random(500, 3000)

        local redis_key = "ntc:HAVEIBEENPWND:" .. crypto.md5(request.account)
        local hash = string.lower(crypto.sha1(request.password))

        local redis_hash_count, err_redis_hget = nauthilus_redis.redis_hget(redis_key, hash:sub(1, 5), "number")
        nauthilus_util.if_error_raise(err_redis_hget)

        if redis_hash_count then
            if nauthilus_util.is_number(redis_hash_count) then
                if redis_hash_count > 0 then
                    -- Required by telegram.lua
                    nauthilus_context.context_set(N .. "_hash_info", hash:sub(1, 5) .. redis_hash_count)

                    nauthilus_builtin.custom_log_add(N .. "_result", "leaked")
                end

                return nauthilus_builtin.ACTION_RESULT_OK
            end
        end

        nauthilus_prometheus.create_gauge_vec(HCCR, "Measure the number of total concurrent HTTP client requests", { "service" })
        nauthilus_prometheus.create_histogram_vec(N .. "_duration_seconds", "HTTP request to the haveibeenpwnd network", { "http" })

        nauthilus_prometheus.increment_gauge(HCCR, { service = N })

        nauthilus_psnet.register_connection_target("api.pwnedpasswords.com", "remote", N)

        local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { http = "get" })
        local result, err = http.get("https://api.pwnedpasswords.com/range/" .. hash:sub(1, 5), {
            timeout = "10s",
            headers = {
                Accept = "*/*",
                ["User-Agent"] = "Nauthilus",
            },
        })
        nauthilus_prometheus.stop_timer(timer)
        nauthilus_util.if_error_raise(err)
        nauthilus_prometheus.decrement_gauge(HCCR, { service = N })

        if result.status_code ~= 200 then
            nauthilus_util.if_error_raise(N .. "_status_code=" .. tostring(result.status_code))
        end

        for line in result.body:gmatch("([^\n]*)\n?") do
            local cmp_hash = strings.split(line, ":")
            if #cmp_hash == 2 and string.lower(cmp_hash[1]) == hash then
                local _, err_redis_hset = nauthilus_redis.redis_hset(redis_key, hash:sub(1, 5), cmp_hash[2])
                nauthilus_util.if_error_raise(err_redis_hset)

                local _, err_redis_expire = nauthilus_redis.redis_expire(redis_key, 3600)
                nauthilus_util.if_error_raise(err_redis_expire)

                -- Required by telegram.lua
                nauthilus_context.context_set(N .. "_hash_info", hash:sub(1, 5) .. cmp_hash[2])
                nauthilus_builtin.custom_log_add(N .. "_action", "leaked")

                local already_sent_mail, err_redis_hget2 = nauthilus_redis.redis_hget(redis_key, "send_mail")
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
                    local smtp_rcpt_to = request.account

                    local mustache, err_tmpl = template.choose("mustache")
                    nauthilus_util.if_error_raise(err_tmpl)

                    local tmpl_data = {
                        account = request.account,
                        hash = hash:sub(1, 5),
                        count = cmp_hash[2],
                        website = os.environ("SSP_WEBSITE")
                    }

                    local err_smtp = nauthilus_mail.send_mail({
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
                        subject = "Password leak detected for your account <" .. request.account .. ">",
                        body = mustache:render(smtp_message, tmpl_data)
                    })
                    nauthilus_util.if_error_raise(err_smtp)

                    _, err_redis_hset = nauthilus_redis.redis_hset(redis_key, "send_mail", 1)
                    nauthilus_util.if_error_raise(err_redis_hset)

                    _, err_redis_expire = nauthilus_redis.redis_expire(redis_key, 86400)
                    nauthilus_util.if_error_raise(err_redis_expire)

                    -- Get result table
                    local rt = nauthilus_context.context_get("rt")
                    if rt == nil then
                        rt = {}
                    end
                    if nauthilus_util.is_table(rt) then
                        rt.action_haveibeenpwnd = true

                        nauthilus_context.context_set("rt", rt)
                    end
                end

                return nauthilus_builtin.ACTION_RESULT_OK
            end
        end

        local _, err_redis_hset = nauthilus_redis.redis_hset(redis_key, hash:sub(1, 5), 0)
        nauthilus_util.if_error_raise(err_redis_hset)

        local _, err_redis_expire = nauthilus_redis.redis_expire(redis_key, 86400)
        nauthilus_util.if_error_raise(err_redis_expire)
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
