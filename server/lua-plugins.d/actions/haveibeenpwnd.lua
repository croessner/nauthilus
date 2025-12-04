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

Please consider changing your password as soon as possible. To do so, please go to the following
website: {{website}}.

Regards

Postmaster
]]

local N = "haveibeenpwnd"

local nauthilus_util = require("nauthilus_util")

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_mail = require("nauthilus_mail")
local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_cache = require("nauthilus_cache")

local crypto = require('glua_crypto')
local http = require("glua_http")
local strings = require("strings")
local template = require("template")

local HCCR = "http_client_concurrent_requests_total"

function nauthilus_call_action(request)
    if not request.no_auth and request.authenticated then
        local redis_key = "ntc:HAVEIBEENPWND:" .. crypto.md5(request.account)
        local hash = string.lower(crypto.sha1(request.password))

        local custom_pool = "default"
        local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
        if custom_pool_name ~= nil and  custom_pool_name ~= "" then
            local err_redis_client

            custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
            nauthilus_util.if_error_raise(err_redis_client)
        end

        -- Fast-path: check local cache first to avoid Redis/HTTP on repeated attempts
        local cache_key = "hibp:" .. (request.account or "") .. ":" .. hash:sub(1, 5)
        local cached = nauthilus_cache.cache_get(cache_key)
        if cached ~= nil then
            if nauthilus_util.is_number(cached) and cached > 0 then
                nauthilus_context.context_set(N .. "_hash_info", hash:sub(1, 5) .. cached)
                nauthilus_builtin.custom_log_add(N .. "_result", "leaked")
            end

            return nauthilus_builtin.ACTION_RESULT_OK
        end

        local redis_hash_count, err_redis_hget = nauthilus_redis.redis_hget(custom_pool, redis_key, hash:sub(1, 5), "number")
        nauthilus_util.if_error_raise(err_redis_hget)

        if redis_hash_count then
            if nauthilus_util.is_number(redis_hash_count) then
                -- Seed local cache for short TTL to reduce repeated lookups across processes
                -- Positive: 3600s, Negative: 600s
                local ttl = (redis_hash_count > 0) and 3600 or 600
                nauthilus_cache.cache_set(cache_key, redis_hash_count, ttl)

                if redis_hash_count > 0 then
                    -- Required by telegram.lua
                    nauthilus_context.context_set(N .. "_hash_info", hash:sub(1, 5) .. redis_hash_count)

                    nauthilus_builtin.custom_log_add(N .. "_result", "leaked")
                end

                return nauthilus_builtin.ACTION_RESULT_OK
            end
        end

        -- Redis gate to avoid repeated external requests for the same account+prefix in a short window
        do
            local gate_key = "ntc:HAVEIBEENPWND:GATE:" .. crypto.md5(request.account) .. ":" .. hash:sub(1, 5)
            local ok_gate, gate_err = nauthilus_redis.redis_set(custom_pool, gate_key, "1", { nx = true, ex = 300 })
            nauthilus_util.if_error_raise(gate_err)
            if ok_gate == nil then
                -- Another worker is or was recently fetching this prefix; skip HTTP
                return nauthilus_builtin.ACTION_RESULT_OK
            end
        end

        nauthilus_prometheus.increment_gauge(HCCR, { service = N })

        local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { http = "get" })
        local result, err = http.get("https://api.pwnedpasswords.com/range/" .. hash:sub(1, 5), {
            timeout = "10s",
            headers = {
                Accept = "*/*",
                ["User-Agent"] = "Nauthilus",
            },
        })
        nauthilus_prometheus.stop_timer(timer)
        nauthilus_prometheus.decrement_gauge(HCCR, { service = N })
        nauthilus_util.if_error_raise(err)

        if result.status_code ~= 200 then
            nauthilus_util.if_error_raise(N .. "_status_code=" .. tostring(result.status_code))
        end

        for line in result.body:gmatch("([^\n]*)\n?") do
            local cmp_hash = strings.split(line, ":")
            if #cmp_hash == 2 and string.lower(cmp_hash[1]) == hash:sub(6) then
                local count = tonumber(cmp_hash[2]) or 0
                local _, err_redis_hset = nauthilus_redis.redis_hset(custom_pool, redis_key, hash:sub(1, 5), count)
                nauthilus_util.if_error_raise(err_redis_hset)

                local _, err_redis_expire = nauthilus_redis.redis_expire(custom_pool, redis_key, 3600)
                nauthilus_util.if_error_raise(err_redis_expire)

                -- Update in-process cache for positive hit (1h TTL)
                nauthilus_cache.cache_set(cache_key, count, 3600)

                -- Required by telegram.lua
                nauthilus_context.context_set(N .. "_hash_info", hash:sub(1, 5) .. count)
                nauthilus_builtin.custom_log_add(N .. "_action", "leaked")

                local script_result, err_run_script = nauthilus_redis.redis_run_script(custom_pool, "", "nauthilus_send_mail_hash", { redis_key }, {})
                nauthilus_util.if_error_raise(err_run_script)

                if script_result[1] == "send_mail" then
                    local smtp_use_lmtp = os.getenv("SMTP_USE_LMTP")
                    local smtp_server = os.getenv("SMTP_SERVER")
                    local smtp_port = os.getenv("SMTP_PORT")
                    local smtp_helo_name = os.getenv("SMTP_HELO_NAME")
                    local smtp_tls = os.getenv("SMTP_TLS")
                    local smtp_starttls = os.getenv("SMTP_STARTTLS")
                    local smtp_username = os.getenv("SMTP_USERNAME")
                    local smtp_password = os.getenv("SMTP_PASSWORD")
                    local smtp_mail_from = os.getenv("SMTP_MAIL_FROM")
                    local smtp_rcpt_to = request.account

                    local mustache, err_tmpl = template.choose("mustache")
                    nauthilus_util.if_error_raise(err_tmpl)

                    local tmpl_data = {
                        account = request.account,
                        hash = hash:sub(1, 5),
                        count = count,
                        website = os.getenv("SSP_WEBSITE")
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

                    _, err_redis_expire = nauthilus_redis.redis_expire(custom_pool, redis_key, 86400)
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

        local _, err_redis_hset = nauthilus_redis.redis_hset(custom_pool, redis_key, hash:sub(1, 5), 0)
        nauthilus_util.if_error_raise(err_redis_hset)

        local _, err_redis_expire = nauthilus_redis.redis_expire(custom_pool, redis_key, 86400)
        nauthilus_util.if_error_raise(err_redis_expire)

        -- Cache negative result shortly to avoid repeated HTTP lookups
        nauthilus_cache.cache_set(cache_key, 0, 600)
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
