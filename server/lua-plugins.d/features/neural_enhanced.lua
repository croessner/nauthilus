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

local N = "neural_enhanced"

function nauthilus_call_neural_network(request)
    if request.no_auth then
        return
    end

    local nauthilus_util = require("nauthilus_util")

    -- Load Redis module
    dynamic_loader("nauthilus_redis")
    local nauthilus_redis = require("nauthilus_redis")

    -- Load Neural module
    dynamic_loader("nauthilus_neural")
    local nauthilus_neural = require("nauthilus_neural")

    -- Get Redis connection
    local redis_pool = "default"
    local redis_handle = nauthilus_redis.get_redis_connection(redis_pool)

    -- Define time window
    local window = 3600 -- 1 hour window
    local username = request.username

    -- Collect global metrics
    local current_metrics_key = "ntc:multilayer:global:current_metrics"

    -- Get global metrics
    local global_auth_rate = 0
    local global_unique_ip_rate = 0
    local global_ip_user_ratio = 0

    -- Get attempts count
    local attempts_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "attempts")
    local attempts = tonumber(attempts_str) or 0

    -- Get unique IPs count
    local unique_ips_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "unique_ips")
    local unique_ips = tonumber(unique_ips_str) or 0

    -- Get unique users count
    local unique_users_str = nauthilus_redis.redis_hget(redis_handle, current_metrics_key, "unique_users")
    local unique_users = tonumber(unique_users_str) or 0

    -- Calculate global metrics
    if window > 0 then
        global_auth_rate = attempts / (window / 60) -- Auth attempts per minute
    end

    if window > 0 then
        global_unique_ip_rate = unique_ips / (window / 60) -- New unique IPs per minute
    end

    if unique_users > 0 then
        global_ip_user_ratio = unique_ips / unique_users -- Ratio of unique IPs to unique usernames
    end

    -- Collect account-specific metrics
    local account_targeting_score = 0
    local account_unique_ip_rate = 0
    local account_fail_ratio = 0

    if username and username ~= "" then
        local account_metrics_key = "ntc:multilayer:account:" .. username .. ":metrics"

        -- Get account unique IPs
        local account_unique_ips_str = nauthilus_redis.redis_hget(redis_handle, account_metrics_key, "unique_ips")
        local account_unique_ips = tonumber(account_unique_ips_str) or 0

        -- Get account failed attempts
        local account_failed_attempts_str = nauthilus_redis.redis_hget(redis_handle, account_metrics_key, "failed_attempts")
        local account_failed_attempts = tonumber(account_failed_attempts_str) or 0

        -- Calculate account metrics
        if window > 0 then
            account_unique_ip_rate = account_unique_ips / (window / 60) -- New unique IPs per minute for this account
        end

        -- Calculate account targeting score (how targeted is this account compared to others)
        if unique_users > 0 and account_unique_ips > 0 then
            -- This score will be high if this account has many unique IPs compared to the average
            account_targeting_score = (account_unique_ips / unique_ips) * unique_users
        end

        -- Calculate account fail ratio
        if account_failed_attempts > 0 then
            -- Get the list of accounts under distributed attack
            local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
            local is_under_attack = nauthilus_redis.redis_zscore(redis_handle, attacked_accounts_key, username)

            if is_under_attack then
                account_fail_ratio = 1.0 -- Max value if account is under attack
            else
                -- Normalize to 0-1 range
                account_fail_ratio = math.min(1.0, account_failed_attempts / 100)
            end
        end
    end

    -- Normalize values to [0, 1] range
    local max_auth_rate = 100 -- Assuming 100 auth attempts per minute is a reasonable max
    local max_unique_ip_rate = 50 -- Assuming 50 new unique IPs per minute is a reasonable max
    local max_ip_user_ratio = 10 -- Assuming 10 IPs per user is a reasonable max
    local max_targeting_score = 10 -- Assuming a targeting score of 10 is a reasonable max
    local max_unique_ip_rate_account = 20 -- Assuming 20 new unique IPs per minute for an account is a reasonable max

    -- Normalize values
    local normalized_global_auth_rate = math.min(1.0, global_auth_rate / max_auth_rate)
    local normalized_global_unique_ip_rate = math.min(1.0, global_unique_ip_rate / max_unique_ip_rate)
    local normalized_global_ip_user_ratio = math.min(1.0, global_ip_user_ratio / max_ip_user_ratio)
    local normalized_account_targeting_score = math.min(1.0, account_targeting_score / max_targeting_score)
    local normalized_account_unique_ip_rate = math.min(1.0, account_unique_ip_rate / max_unique_ip_rate_account)
    -- account_fail_ratio is already normalized to [0, 1]

    -- Add these features to the neural network
    local additional_features_one_hot = {
        global_auth_rate = normalized_global_auth_rate,
        global_unique_ip_rate = normalized_global_unique_ip_rate,
        global_ip_user_ratio = normalized_global_ip_user_ratio,
        account_targeting_score = normalized_account_targeting_score,
        account_unique_ip_rate = normalized_account_unique_ip_rate,
        account_fail_ratio = account_fail_ratio
    }

    -- Add to neural network using one-hot encoding
    nauthilus_neural.add_additional_features(additional_features_one_hot, "one-hot")

    -- Add log
    local logs = {}
    logs.caller = N .. ".lua"
    logs.level = "info"
    logs.message = "Enhanced neural features added"
    logs.global_auth_rate = global_auth_rate
    logs.global_unique_ip_rate = global_unique_ip_rate
    logs.global_ip_user_ratio = global_ip_user_ratio
    logs.account_targeting_score = account_targeting_score
    logs.account_unique_ip_rate = account_unique_ip_rate
    logs.account_fail_ratio = account_fail_ratio
    logs.normalized_global_auth_rate = normalized_global_auth_rate
    logs.normalized_global_unique_ip_rate = normalized_global_unique_ip_rate
    logs.normalized_global_ip_user_ratio = normalized_global_ip_user_ratio
    logs.normalized_account_targeting_score = normalized_account_targeting_score
    logs.normalized_account_unique_ip_rate = normalized_account_unique_ip_rate

    nauthilus_util.print_result({ log_format = "json" }, logs)

    -- Add to custom log for monitoring
    nauthilus_builtin.custom_log_add(N .. "_global_auth_rate", global_auth_rate)
    nauthilus_builtin.custom_log_add(N .. "_global_unique_ip_rate", global_unique_ip_rate)
    nauthilus_builtin.custom_log_add(N .. "_global_ip_user_ratio", global_ip_user_ratio)
    nauthilus_builtin.custom_log_add(N .. "_account_targeting_score", account_targeting_score)
    nauthilus_builtin.custom_log_add(N .. "_account_unique_ip_rate", account_unique_ip_rate)
    nauthilus_builtin.custom_log_add(N .. "_account_fail_ratio", account_fail_ratio)
    nauthilus_builtin.custom_log_add(N .. "_normalized_global_auth_rate", normalized_global_auth_rate)
    nauthilus_builtin.custom_log_add(N .. "_normalized_global_unique_ip_rate", normalized_global_unique_ip_rate)
    nauthilus_builtin.custom_log_add(N .. "_normalized_global_ip_user_ratio", normalized_global_ip_user_ratio)
    nauthilus_builtin.custom_log_add(N .. "_normalized_account_targeting_score", normalized_account_targeting_score)
    nauthilus_builtin.custom_log_add(N .. "_normalized_account_unique_ip_rate", normalized_account_unique_ip_rate)

    return
end
