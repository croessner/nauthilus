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
    local sha1, err_upload = nauthilus_redis.redis_upload_script(script, upload_script_name)

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
    nauthilus_prometheus.create_histogram_vec("blocklist_duration_seconds", "HTTP request to the blocklist service", { "http" })
    nauthilus_psnet.register_connection_target(os.getenv("BLOCKLIST_SERVICE_ENDPOINT"), "remote", "blocklist")

    -- geoip.lua
    nauthilus_prometheus.create_histogram_vec("geoippolicyd_duration_seconds", "HTTP request to the geoip-policyd service", { "http" })
    nauthilus_prometheus.create_counter_vec("geoippolicyd_count", "Count GeoIP countries", { "country", "status" })
    nauthilus_psnet.register_connection_target(os.getenv("GEOIP_POLICY_SERVICE_ENDPOINT"), "remote", "geoippolicyd")

    result.status = "finished"

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end
end