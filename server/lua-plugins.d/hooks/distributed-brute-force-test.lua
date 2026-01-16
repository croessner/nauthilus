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

local nauthilus_http_request = require("nauthilus_http_request")
local nauthilus_redis = require("nauthilus_redis")

local time = require("time")

local N = "distributed-brute-force-test"

local NAUTHILUS_WARMUP_WINDOW_SECONDS = nauthilus_util.getenv("NAUTHILUS_WARMUP_WINDOW_SECONDS", "86400")

-- Ensure system start and warm-up settings exist; return settings table
local function ensure_startup_settings(redis_handle)
    local settings_key = "ntc:multilayer:global:settings"
    local settings = nauthilus_redis.redis_hgetall(redis_handle, settings_key) or {}

    -- system_started_at: unix timestamp
    if not settings["system_started_at"] or settings["system_started_at"] == "" then
        local now = time.unix()
        -- Persist only if missing
        nauthilus_redis.redis_hset(redis_handle, settings_key, "system_started_at", tostring(now))
        settings["system_started_at"] = tostring(now)
    end

    -- warmup_window_seconds: from env or default 86400 (24h)
    local env_warmup = NAUTHILUS_WARMUP_WINDOW_SECONDS
    local default_warmup = tostring(86400)
    local warmup_value = env_warmup and tostring(tonumber(env_warmup) or 0) or nil
    if not warmup_value or tonumber(warmup_value) == nil or tonumber(warmup_value) <= 0 then
        warmup_value = default_warmup
    end

    if not settings["warmup_window_seconds"] or settings["warmup_window_seconds"] == "" then
        nauthilus_redis.redis_hset(redis_handle, settings_key, "warmup_window_seconds", warmup_value)
        settings["warmup_window_seconds"] = warmup_value
    end

    return settings
end

-- Compute warm-up diagnostics table
local function get_warmup(redis_handle)
    local settings = ensure_startup_settings(redis_handle)
    local now = time.unix()
    local started_at = tonumber(settings["system_started_at"]) or now
    local warmup_window = tonumber(settings["warmup_window_seconds"]) or 86400
    local uptime = math.max(0, now - started_at)
    local progress = 0.0
    if warmup_window > 0 then
        progress = math.min(1.0, uptime / warmup_window)
    end
    return {
        system_started_at = started_at,
        uptime_seconds = uptime,
        warmup_window_seconds = warmup_window,
        warmup_progress = progress,
        warmup_complete = progress >= 1.0,
        settings = settings or {}
    }
end

-- Helper function to generate random IP addresses
local function generate_random_ip()
    local ip = math.random(1, 255) .. "." .. 
               math.random(0, 255) .. "." .. 
               math.random(0, 255) .. "." .. 
               math.random(1, 255)
    return ip
end

-- Helper function to simulate a distributed brute force attack
local function simulate_distributed_attack(redis_handle, username, num_ips, country_code)
    local timestamp = time.unix()
    local window_sizes = {60, 300, 900, 3600} -- 1min, 5min, 15min, 1hour

    -- Simulate multiple IPs attempting to access the same account
    for i = 1, num_ips do
        local ip = generate_random_ip()

        -- Build batched pipeline commands to reduce round trips
        local pipeline_cmds = {}

        -- Track global authentication metrics in sliding windows
        for _, window in ipairs(window_sizes) do
            local request_id = "test-" .. username .. "-" .. i

            -- Add authentication attempt
            local key = "nauthilus:global:auth_attempts:" .. window
            table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {key}, {timestamp, request_id, 0, timestamp - window, window * 2}})

            -- Add unique IP
            local ip_key_w = "nauthilus:global:unique_ips:" .. window
            table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {ip_key_w}, {timestamp, ip, 0, timestamp - window, window * 2}})

            -- Add unique username
            local user_key = "nauthilus:global:unique_users:" .. window
            table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {user_key}, {timestamp, username, 0, timestamp - window, window * 2}})
        end

        -- Track account-specific metrics
        local window = 3600 -- 1 hour window

        -- Add IP to account's unique IPs
        local ip_key = "nauthilus:account:" .. username .. ":ips:" .. window
        table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {ip_key}, {timestamp, ip, 0, timestamp - window, window * 2}})

        -- Add failed attempt for account
        local fail_key = "nauthilus:account:" .. username .. ":fails:" .. window
        table.insert(pipeline_cmds, {"run_script", "ZAddRemExpire", {fail_key}, {timestamp, "test-fail-" .. i, 0, timestamp - window, window * 2}})

        -- Increment country count and country set if country code is provided
        if country_code and country_code ~= "" then
            local country_key = "ntc:multilayer:global:country:" .. country_code
            table.insert(pipeline_cmds, {"run_script", "IncrementAndExpire", {country_key}, {24 * 3600}})

            local countries_key = "ntc:multilayer:global:countries"
            table.insert(pipeline_cmds, {"run_script", "AddToSetAndExpire", {countries_key}, {country_code, 24 * 3600}})
        end

        -- Execute the pipeline batch
        local _, pipe_err = nauthilus_redis.redis_pipeline(redis_handle, "write", pipeline_cmds)
        nauthilus_util.if_error_raise(pipe_err)
    end

    -- Update global metrics
    local current_metrics_key = "ntc:multilayer:global:current_metrics"

    -- Get current metrics (bundle via HMGET)
    local res, rerr = nauthilus_redis.redis_pipeline(redis_handle, "read", {
        {"hmget", current_metrics_key, "attempts", "unique_ips", "unique_users"}
    })
    nauthilus_util.if_error_raise(rerr)
    local attempts, unique_ips, unique_users = 0, 0, 0
    if type(res) == "table" and type(res[1]) == "table" and res[1].ok ~= false and type(res[1].value) == "table" then
        local v = res[1].value
        attempts = tonumber(v[1] or 0) or 0
        unique_ips = tonumber(v[2] or 0) or 0
        unique_users = tonumber(v[3] or 0) or 0
    end

    -- Update metrics
    attempts = attempts + num_ips
    unique_ips = unique_ips + num_ips
    unique_users = unique_users + 1

    -- Calculate derived metrics
    local ips_per_user = unique_ips / math.max(unique_users, 1)

    -- Store updated metrics
    local _, err_script = nauthilus_redis.redis_run_script(
        redis_handle, 
        "", 
        "HSetMultiExpire", 
        {current_metrics_key}, 
        {
            3600, -- Expire after 1 hour
            "attempts", attempts,
            "unique_ips", unique_ips,
            "unique_users", unique_users,
            "ips_per_user", ips_per_user
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Mark account as under attack if many IPs are targeting it
    if num_ips > 10 then
        local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
        nauthilus_redis.redis_zadd(redis_handle, attacked_accounts_key, {num_ips, username})
        nauthilus_redis.redis_expire(redis_handle, attacked_accounts_key, 3600) -- Expire after 1 hour
    end

    return true
end

-- Helper function to check if the attack was detected
local function check_attack_detection(redis_handle, username)
    local detection_result = {}

    -- Check threat level
    local threat_level = nauthilus_redis.redis_hget(redis_handle, "ntc:multilayer:global:settings", "threat_level") or "0.0"
    detection_result.threat_level = tonumber(threat_level) or 0.0

    -- Check if account is marked as under attack
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    local attack_score = nauthilus_redis.redis_zscore(redis_handle, attacked_accounts_key, username)
    detection_result.account_under_attack = (attack_score ~= nil)
    detection_result.attack_score = attack_score

    -- Check protection measures
    local settings = nauthilus_redis.redis_hgetall(redis_handle, "ntc:multilayer:global:settings")
    detection_result.captcha_enabled = nauthilus_util.toboolean(settings.captcha_enabled)
    detection_result.rate_limit_enabled = nauthilus_util.toboolean(settings.rate_limit_enabled)
    detection_result.monitoring_mode = nauthilus_util.toboolean(settings.monitoring_mode)

    -- Check if account is in captcha accounts
    local captcha_accounts_key = "ntc:multilayer:global:captcha_accounts"
    local is_captcha_account = nauthilus_redis.redis_sismember(redis_handle, captcha_accounts_key, username)
    detection_result.is_captcha_account = is_captcha_account

    -- Determine if attack was detected
    detection_result.attack_detected = (
        detection_result.threat_level >= 0.5 or
        detection_result.account_under_attack or
        detection_result.captcha_enabled or
        detection_result.rate_limit_enabled or
        detection_result.monitoring_mode or
        detection_result.is_captcha_account
    )

    return detection_result
end

function nauthilus_run_hook(logging, session)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"
    result.session = session

    -- Get Redis connection
    local redis_pool = "default"
    local redis_handle = nauthilus_redis.get_redis_connection(redis_pool)

    -- Get action parameter
    local action = nauthilus_http_request.get_http_query_param("action")

    if not action or action == "" then
        result.level = "error"
        result.status = "error"
        result.message = "Missing required parameter: action"
        return result
    end

    if action == "simulate_attack" then
        -- Get parameters
        local username = nauthilus_http_request.get_http_query_param("username")
        local num_ips_str = nauthilus_http_request.get_http_query_param("num_ips")
        local country_code = nauthilus_http_request.get_http_query_param("country_code")

        -- Validate parameters
        if not username or username == "" then
            result.level = "error"
            result.status = "error"
            result.message = "Missing required parameter: username"
            nauthilus_util.print_result(logging, result)
            return result
        end

        local num_ips = tonumber(num_ips_str) or 20 -- Default to 20 IPs

        -- Simulate attack
        if not simulate_distributed_attack(redis_handle, username, num_ips, country_code) then
            result.level = "error"
            result.status = "error"
            result.message = "Failed to simulate attack"
            nauthilus_util.print_result(logging, result)

            return result
        end

        result.status = "success"
        result.message = "Distributed brute force attack simulated successfully"
        result.username = username
        result.num_ips = num_ips
        result.country_code = country_code

        -- Include warm-up diagnostics
        local warmup = get_warmup(redis_handle)
        result.warmup = warmup
        if not warmup.warmup_complete then
            result.message = result.message .. " (Note: system is in warm-up; sliding windows may not reflect steady-state yet.)"
        end
    elseif action == "check_detection" then
        -- Get username parameter
        local username = nauthilus_http_request.get_http_query_param("username")

        -- Validate parameters
        if not username or username == "" then
            result.level = "error"
            result.status = "error"
            result.message = "Missing required parameter: username"
            nauthilus_util.print_result(logging, result)

            return result
        end

        -- Check if attack was detected
        local detection_result = check_attack_detection(redis_handle, username)

        result.status = "success"
        result.message = "Detection check completed"
        result.username = username
        result.detection_result = detection_result

        -- Include warm-up diagnostics
        local warmup = get_warmup(redis_handle)
        result.warmup = warmup
        if not warmup.warmup_complete then
            result.message = result.message .. " (Note: system is in warm-up; sliding windows may not reflect steady-state yet.)"
        end
    elseif action == "run_test" then
        -- Get parameters
        local username = nauthilus_http_request.get_http_query_param("username")
        local num_ips_str = nauthilus_http_request.get_http_query_param("num_ips")
        local country_code = nauthilus_http_request.get_http_query_param("country_code")

        -- Validate parameters
        if not username or username == "" then
            result.level = "error"
            result.status = "error"
            result.message = "Missing required parameter: username"
            nauthilus_util.print_result(logging, result)

            return result
        end

        local num_ips = tonumber(num_ips_str) or 20 -- Default to 20 IPs

        -- Reset any existing protection measures
        local _, err_reset = nauthilus_redis.redis_run_script(
            redis_handle, 
            "", 
            "HSetMultiExpire", 
            {"ntc:multilayer:global:settings"}, 
            {
                3600, -- Expire after 1 hour
                "captcha_enabled", "false",
                "rate_limit_enabled", "false",
                "monitoring_mode", "false",
                "threat_level", "0.0"  -- Reset threat level
            }
        )

        -- Check for errors during reset
        if err_reset then
            result.level = "error"
            result.status = "error"
            result.message = "Failed to reset protection measures"
            result.error = err_reset
            nauthilus_util.print_result(logging, result)

            return result
        end

        -- Simulate attack
        if not simulate_distributed_attack(redis_handle, username, num_ips, country_code) then
            result.level = "error"
            result.status = "error"
            result.message = "Failed to simulate attack"
            nauthilus_util.print_result(logging, result)

            return result
        end

        -- Wait a moment for the system to process the attack
        time.sleep(1)

        -- Check if attack was detected
        local detection_result = check_attack_detection(redis_handle, username)

        result.status = "success"
        result.message = "Test completed"
        result.username = username
        result.num_ips = num_ips
        result.country_code = country_code
        result.detection_result = detection_result

        -- Include warm-up diagnostics
        local warmup = get_warmup(redis_handle)
        result.warmup = warmup

        -- Determine test result
        if detection_result.attack_detected then
            result.test_result = "PASS"
            result.test_message = "Distributed brute force attack was successfully detected"
        else
            result.test_result = "FAIL"
            result.test_message = "Distributed brute force attack was not detected"
        end

        if not warmup.warmup_complete then
            result.test_message = result.test_message .. " (Note: system is in warm-up; sliding windows may not reflect steady-state yet.)"
        end
    else
        result.level = "error"
        result.status = "error"
        result.message = "Invalid action: " .. action
    end

    nauthilus_util.log(logging, result.level or "info", result)

    return result
end
