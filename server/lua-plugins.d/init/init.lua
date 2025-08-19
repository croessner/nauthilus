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

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_prometheus")
local nauthilus_prometheus = require("nauthilus_prometheus")

dynamic_loader("nauthilus_psnet")
local nauthilus_psnet = require("nauthilus_psnet")

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

local N = "init"

function nauthilus_run_hook(logging)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"

    local custom_pool = "default"
    local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
    if custom_pool_name ~= nil and  custom_pool_name ~= "" then
        local _, err_redis_reg = nauthilus_redis.register_redis_pool(custom_pool_name, "standalone", {
            address = "localhost:6379",
            password = "",
            db = 3,
            pool_size = 10,
            min_idle_conns = 1,
            tls_enabled = false
        })
        nauthilus_util.if_error_raise(err_redis_reg)

        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    local script = [[
        local redis_key = KEYS[1]
        local send_mail = redis.call('HGET', redis_key, 'send_mail')

        if send_mail == false then
            redis.call('HSET', redis_key, 'send_mail', '1')

            return {'send_email', redis_key}
        else
            return {'email_already_sent'}
        end
    ]]

    local upload_script_name = "nauthilus_send_mail_hash"
    local sha1, err_upload = nauthilus_redis.redis_upload_script(custom_pool, script, upload_script_name)

    nauthilus_util.if_error_raise(err_upload)

    result[upload_script_name] = sha1

    -- common
    nauthilus_prometheus.create_gauge_vec("http_client_concurrent_requests_total", "Measure the number of total concurrent HTTP client requests", { "service" })

    -- analytics.lua
    nauthilus_prometheus.create_counter_vec("analytics_count", "Count the criteria which caused rejection", {"feature"})

    -- haveibeenpwnd.lua
    nauthilus_prometheus.create_histogram_vec("haveibeenpwnd_duration_seconds", "HTTP request to the haveibeenpwnd network", { "http" })
    nauthilus_psnet.register_connection_target("api.pwnedpasswords.com:443", "remote", "haveibeenpwnd")

    -- telegram.lua
    nauthilus_prometheus.create_histogram_vec("telegram_duration_seconds", "HTTP request to the telegram network", { "bot" })

    -- backend.lua
    nauthilus_psnet.register_connection_target("127.0.0.1:3306", "remote", "backend")

    -- blocklist.lua
    local blocklist_addr = os.getenv("BLOCKLIST_SERVICE_ENDPOINT")
    if blocklist_addr then
        nauthilus_prometheus.create_histogram_vec("blocklist_duration_seconds", "HTTP request to the blocklist service", { "http" })
        nauthilus_psnet.register_connection_target(blocklist_addr, "remote", "blocklist")
    end

    -- geoip.lua
    local geoip_policyd_addr = os.getenv("GEOIP_POLICY_SERVICE_ENDPOINT")
    if geoip_policyd_addr then
        nauthilus_prometheus.create_histogram_vec("geoippolicyd_duration_seconds", "HTTP request to the geoip-policyd service", { "http" })
        nauthilus_prometheus.create_counter_vec("geoippolicyd_count", "Count GeoIP countries", { "country", "status" })
        nauthilus_psnet.register_connection_target(geoip_policyd_addr, "remote", "geoippolicyd")
    end

    -- neural.lua
    if geoip_policyd_addr then
        nauthilus_prometheus.create_histogram_vec("neural_duration_seconds", "HTTP request to the neural service", { "http" })
    end

    -- failed_login_hotspot.lua
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_user_score", "Failed login ZSET score for username", { "username" })
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_user_rank", "Rank within top failed-logins for username (lower is hotter)", { "username" })
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_top_score", "Top-N failed login scores snapshot", { "rank", "username" })
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_topn_size", "Size of Top-N snapshot for failed logins", { })
    nauthilus_prometheus.create_counter_vec("failed_login_hotspot_count", "Count of failed-login hotspot triggers", { "state" })

    -- security_* metrics from attacker_detection_ideas.md
    -- Note: For per-user metrics we include a 'username' label to avoid overwriting and to make values inspectable per account.
    nauthilus_prometheus.create_gauge_vec("security_unique_ips_per_user", "Unique IPs seen per user over time windows", { "username", "window" })
    nauthilus_prometheus.create_gauge_vec("security_account_fail_budget_used", "Number of failures for user over time windows", { "username", "window" })
    nauthilus_prometheus.create_gauge_vec("security_global_ips_per_user", "Global ratio of unique IPs to unique users over time windows", { "window" })
    nauthilus_prometheus.create_gauge_vec("security_accounts_in_protection_mode_total", "Current number of accounts in protection mode", { })
    nauthilus_prometheus.create_counter_vec("security_sprayed_password_tokens_total", "Count of observed privacy-preserving sprayed password tokens", { "window" })
    nauthilus_prometheus.create_counter_vec("security_stepup_challenges_issued_total", "Number of step-up challenges issued (hint flags set)", { })
    nauthilus_prometheus.create_counter_vec("security_pow_challenges_issued_total", "Number of proof-of-work challenges issued", { })
    nauthilus_prometheus.create_counter_vec("security_slow_attack_suspicions_total", "Heuristic slow-attack suspicions", { })

    result.status = "finished"

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end
end
