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

local N = "dynamic_response"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_mail")
local nauthilus_mail = require("nauthilus_mail")

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

dynamic_loader("nauthilus_context")
local nauthilus_context = require("nauthilus_context")

dynamic_loader("nauthilus_gll_template")
local template = require("template")

-- Email template for administrator notifications
local admin_email_template = [[
Subject: [NAUTHILUS ALERT] {{subject}}

Dear Administrator,

A security alert has been detected by the Nauthilus system:

Alert: {{subject}}
Timestamp: {{timestamp}}

Metrics:
{{#metrics}}
- {{key}}: {{value}}
{{/metrics}}

Please review this alert and take appropriate action if necessary.

Regards,
Nauthilus Security System
]]

-- Notify administrators about the threat
local function notify_administrators(subject, metrics)
    -- Log the notification

    local notify_logs = {}
    notify_logs.caller = N .. ".lua"
    notify_logs.level = "warning"
    notify_logs.message = subject
    notify_logs.metrics = metrics
    notify_logs.timestamp = os.time()

    nauthilus_util.print_result({ log_format = "json" }, notify_logs)

    -- Send email notification
    -- Get SMTP configuration from environment variables
    local smtp_use_lmtp = os.getenv("SMTP_USE_LMTP")
    local smtp_server = os.getenv("SMTP_SERVER")
    local smtp_port = os.getenv("SMTP_PORT")
    local smtp_helo_name = os.getenv("SMTP_HELO_NAME")
    local smtp_tls = os.getenv("SMTP_TLS")
    local smtp_starttls = os.getenv("SMTP_STARTTLS")
    local smtp_username = os.getenv("SMTP_USERNAME")
    local smtp_password = os.getenv("SMTP_PASSWORD")
    local smtp_mail_from = os.getenv("SMTP_MAIL_FROM")

    -- Get admin email addresses from environment variable (comma-separated list)
    local admin_emails_str = os.getenv("ADMIN_EMAIL_ADDRESSES")
    if not admin_emails_str or admin_emails_str == "" then
        -- No admin emails configured, just log and return
        local error_logs = {}
        error_logs.caller = N .. ".lua"
        error_logs.level = "error"
        error_logs.message = "No admin email addresses configured for notifications"
        nauthilus_util.print_result({ log_format = "json" }, error_logs)
        return
    end

    -- Parse admin email addresses
    local admin_emails = {}
    for email in string.gmatch(admin_emails_str, "([^,]+)") do
        -- Trim whitespace
        email = string.match(email, "^%s*(.-)%s*$")
        if email ~= "" then
            table.insert(admin_emails, email)
        end
    end

    -- Prepare template data
    local timestamp_str = os.date("%Y-%m-%d %H:%M:%S", os.time())

    -- Convert metrics table to array of key-value pairs for template
    local metrics_array = {}
    for k, v in pairs(metrics) do
        if type(v) == "table" then
            -- Handle nested tables (like suspicious_regions)
            local value_str = ""
            for _, item in ipairs(v) do
                if value_str ~= "" then
                    value_str = value_str .. ", "
                end
                value_str = value_str .. tostring(item)
            end
            table.insert(metrics_array, {key = k, value = value_str})
        else
            table.insert(metrics_array, {key = k, value = tostring(v)})
        end
    end

    local tmpl_data = {
        subject = subject,
        timestamp = timestamp_str,
        metrics = metrics_array
    }

    -- Render email template
    local mustache, err_tmpl = template.choose("mustache")
    if err_tmpl then
        local error_logs = {}
        error_logs.caller = N .. ".lua"
        error_logs.level = "error"
        error_logs.message = "Failed to initialize template engine"
        error_logs.error = err_tmpl
        nauthilus_util.print_result({ log_format = "json" }, error_logs)
        return
    end

    local email_body = mustache:render(admin_email_template, tmpl_data)

    -- Send email to administrators
    local err_smtp = nauthilus_mail.send_mail({
        lmtp = nauthilus_util.toboolean(smtp_use_lmtp),
        server = smtp_server,
        port = tonumber(smtp_port),
        helo_name = smtp_helo_name,
        username = smtp_username,
        password = smtp_password,
        tls = nauthilus_util.toboolean(smtp_tls),
        starttls = nauthilus_util.toboolean(smtp_starttls),
        from = smtp_mail_from,
        to = admin_emails,
        subject = "[NAUTHILUS ALERT] " .. subject,
        body = email_body
    })

    if err_smtp then
        local error_logs = {}
        error_logs.caller = N .. ".lua"
        error_logs.level = "error"
        error_logs.message = "Failed to send admin notification email"
        error_logs.error = err_smtp
        nauthilus_util.print_result({ log_format = "json" }, error_logs)
    else
        local success_logs = {}
        success_logs.caller = N .. ".lua"
        success_logs.level = "info"
        success_logs.message = "Admin notification email sent successfully"
        success_logs.recipients = #admin_emails
        nauthilus_util.print_result({ log_format = "json" }, success_logs)
    end
end

-- Apply severe measures for high threat levels
local function apply_severe_measures(redis_handle, metrics)
    -- Enable global captcha using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        redis_handle, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Enable for 1 hour
            "captcha_enabled", "true",
            "rate_limit_enabled", "true",
            "rate_limit_max", "10" -- 10 requests per minute
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Enable geographic filtering if suspicious regions are detected using atomic Redis Lua script
    if metrics.suspicious_regions and #metrics.suspicious_regions > 0 then
        local args = {3600} -- Expire after 1 hour
        for _, region in ipairs(metrics.suspicious_regions) do
            table.insert(args, region)
        end

        local _, err_script = nauthilus_redis.redis_run_script(
            redis_handle, 
            "", 
            "SAddMultiExpire", 
            {"ntc:multilayer:global:blocked_regions"}, 
            args
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Increase ML sensitivity using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        redis_handle, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Enable for 1 hour
            "ml_threshold", "0.5" -- Lower threshold for 1 hour
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Notify administrators
    notify_administrators("SEVERE THREAT ALERT", metrics)
end

-- Apply high measures for high threat levels
local function apply_high_measures(redis_handle, metrics)
    -- Enable targeted captcha for affected accounts using atomic Redis Lua script
    if metrics.targeted_accounts and #metrics.targeted_accounts > 0 then
        local args = {3600} -- Expire after 1 hour
        for _, account in ipairs(metrics.targeted_accounts) do
            table.insert(args, account)
        end

        local _, err_script = nauthilus_redis.redis_run_script(
            redis_handle, 
            "", 
            "SAddMultiExpire", 
            {"ntc:multilayer:global:captcha_accounts"}, 
            args
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Enable targeted rate limiting for suspicious IPs using atomic Redis Lua script
    if metrics.suspicious_ips and #metrics.suspicious_ips > 0 then
        local args = {3600} -- Expire after 1 hour
        for _, ip in ipairs(metrics.suspicious_ips) do
            table.insert(args, ip)
        end

        local _, err_script = nauthilus_redis.redis_run_script(
            redis_handle, 
            "", 
            "SAddMultiExpire", 
            {"ntc:multilayer:global:rate_limited_ips"}, 
            args
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Notify administrators
    notify_administrators("HIGH THREAT ALERT", metrics)
end

-- Apply moderate measures for moderate threat levels
local function apply_moderate_measures(redis_handle, metrics)
    -- Enable monitoring mode using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        redis_handle, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Enable for 1 hour
            "monitoring_mode", "true"
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Notify administrators
    notify_administrators("MODERATE THREAT ALERT", metrics)
end

function nauthilus_call_action(request)
    if request.no_auth then
        return
    end

    -- Get Redis connection
    local redis_pool = "default"
    local redis_handle = nauthilus_redis.get_redis_connection(redis_pool)

    -- Get current timestamp
    local timestamp = os.time()
    local username = request.username
    local client_ip = request.client_ip

    -- Calculate threat level based on various factors
    local threat_level = 0.0
    local metrics = {}

    -- Check if this account is under distributed attack
    local is_account_under_attack = false
    if username and username ~= "" then
        local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
        local attack_score = nauthilus_redis.redis_zscore(redis_handle, attacked_accounts_key, username)
        if attack_score then
            is_account_under_attack = true
            threat_level = math.max(threat_level, 0.7) -- High threat level if account is under attack
            metrics.targeted_accounts = {username}
        end
    end

    -- Check global metrics for abnormal patterns
    local current_metrics_key = "ntc:multilayer:global:current_metrics"

    -- Get global metrics
    local attempts_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "attempts")
    local attempts = tonumber(attempts_str) or 0

    local unique_ips_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "unique_ips")
    local unique_ips = tonumber(unique_ips_str) or 0

    local unique_users_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "unique_users")
    local unique_users = tonumber(unique_users_str) or 0

    local ips_per_user_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "ips_per_user")
    local ips_per_user = tonumber(ips_per_user_str) or 0

    -- Store metrics for response
    metrics.attempts = attempts
    metrics.unique_ips = unique_ips
    metrics.unique_users = unique_users
    metrics.ips_per_user = ips_per_user

    -- Check for abnormal global patterns
    if ips_per_user > 10 then
        -- Many IPs per user indicates a distributed attack
        threat_level = math.max(threat_level, 0.8)
    elseif ips_per_user > 5 then
        threat_level = math.max(threat_level, 0.6)
    end

    -- Check historical patterns to detect sudden spikes
    local hour_key = os.date("%Y-%m-%d-%H", timestamp - 3600) -- Previous hour
    local historical_metrics_key = "ntc:multilayer:global:historical_metrics:" .. hour_key

    local prev_attempts_str = nauthilus_redis.redis_hget(redis_handle, historical_metrics_key, "attempts")
    local prev_attempts = tonumber(prev_attempts_str) or 0

    local prev_unique_ips_str = nauthilus_redis.redis_hget(redis_handle, historical_metrics_key, "unique_ips")
    local prev_unique_ips = tonumber(prev_unique_ips_str) or 0

    -- Calculate rate of change
    local attempts_change = 0
    local ips_change = 0

    if prev_attempts > 0 then
        attempts_change = (attempts - prev_attempts) / prev_attempts
    end

    if prev_unique_ips > 0 then
        ips_change = (unique_ips - prev_unique_ips) / prev_unique_ips
    end

    -- Store change metrics
    metrics.attempts_change = attempts_change
    metrics.ips_change = ips_change

    -- Check for sudden spikes
    if attempts_change > 1.0 or ips_change > 1.0 then
        -- More than 100% increase indicates a sudden spike
        threat_level = math.max(threat_level, 0.9)
    elseif attempts_change > 0.5 or ips_change > 0.5 then
        -- More than 50% increase indicates a significant change
        threat_level = math.max(threat_level, 0.7)
    end

    -- Get suspicious regions based on IP geolocation
    local suspicious_regions = {}

    -- Get country code from context (set by geoip.lua)
    local iso_codes_seen = nauthilus_context.context_get("geoippolicyd_iso_codes_seen")
    local country_code = ""

    -- Check if we have country code information
    if iso_codes_seen and #iso_codes_seen > 0 then
        -- Use the first country code from the list
        country_code = iso_codes_seen[1]
    end

    if country_code and country_code ~= "" then
        -- Add country code to custom log for debugging
        nauthilus_builtin.custom_log_add(N .. "_country_code", country_code)

        -- Get count of attempts from this country
        local country_key = "ntc:multilayer:global:country:" .. country_code
        local country_count = nauthilus_redis.redis_get(redis_handle, country_key) or "0"
        country_count = tonumber(country_count) or 0

        -- Increment country count using atomic Redis Lua script
        local _, err_script = nauthilus_redis.redis_run_script(
            redis_handle, 
            "", 
            "IncrementAndExpire", 
            {country_key}, 
            {24 * 3600} -- Expire after 24 hours
        )
        nauthilus_util.if_error_raise(err_script)

        -- Get total countries using atomic Redis Lua script
        local countries_key = "ntc:multilayer:global:countries"
        local _, err_script = nauthilus_redis.redis_run_script(
            redis_handle, 
            "", 
            "AddToSetAndExpire", 
            {countries_key}, 
            {country_code, 24 * 3600} -- Expire after 24 hours
        )
        nauthilus_util.if_error_raise(err_script)

        local total_countries = nauthilus_redis.redis_scard(redis_handle, countries_key) or 1

        -- If this country has a disproportionate number of attempts, mark it as suspicious
        if total_countries > 1 and country_count > (attempts / total_countries) * 2 then
            table.insert(suspicious_regions, country_code)
        end
    end

    metrics.suspicious_regions = suspicious_regions

    -- Store suspicious IPs
    metrics.suspicious_ips = {}

    -- If this is a failed authentication attempt, add the IP to suspicious IPs
    if not request.authenticated and client_ip and client_ip ~= "" then
        table.insert(metrics.suspicious_ips, client_ip)
    end

    -- Apply dynamic response based on threat level
    if threat_level >= 0.9 then
        -- Severe threat: Implement strict measures
        apply_severe_measures(redis_handle, metrics)

        -- Log the response
        local severe_logs = {}
        severe_logs.caller = N .. ".lua"
        severe_logs.level = "warning"
        severe_logs.message = "Severe threat detected, implementing strict measures"
        severe_logs.threat_level = threat_level
        severe_logs.metrics = metrics

        nauthilus_util.print_result({ log_format = "json" }, severe_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "severe")
    elseif threat_level >= 0.7 then
        -- High threat: Implement moderate measures
        apply_high_measures(redis_handle, metrics)

        -- Log the response
        local high_logs = {}
        high_logs.caller = N .. ".lua"
        high_logs.level = "warning"
        high_logs.message = "High threat detected, implementing moderate measures"
        high_logs.threat_level = threat_level
        high_logs.metrics = metrics

        nauthilus_util.print_result({ log_format = "json" }, high_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "high")
    elseif threat_level >= 0.5 then
        -- Moderate threat: Implement light measures
        apply_moderate_measures(redis_handle, metrics)

        -- Log the response
        local moderate_logs = {}
        moderate_logs.caller = N .. ".lua"
        moderate_logs.level = "warning"
        moderate_logs.message = "Moderate threat detected, implementing light measures"
        moderate_logs.threat_level = threat_level
        moderate_logs.metrics = metrics

        nauthilus_util.print_result({ log_format = "json" }, moderate_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "moderate")
    else
        -- Low threat: No special measures needed
        -- Log the normal state
        local normal_logs = {}
        normal_logs.caller = N .. ".lua"
        normal_logs.level = "info"
        normal_logs.message = "Normal operation, no special measures needed"
        normal_logs.threat_level = threat_level
        normal_logs.metrics = metrics

        nauthilus_util.print_result({ log_format = "json" }, normal_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "normal")
    end

    -- Store the current threat level in Redis for other components to use using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        redis_handle, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Expire after 1 hour
            "threat_level", threat_level
        }
    )
    nauthilus_util.if_error_raise(err_script)

    return nauthilus_builtin.ACTION_RESULT_OK
end
