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

-- Derives a feature signal from ntc:top_failed_logins (count/rank by username)
-- This feature is read-only against Redis and can be enabled safely. It enriches
-- the runtime table (rt) for downstream actions like analytics and telegram.

local N = "failed_login_hotspot"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

dynamic_loader("nauthilus_context")
local nauthilus_context = require("nauthilus_context")

dynamic_loader("nauthilus_prometheus")
local nauthilus_prometheus = require("nauthilus_prometheus")

-- Env knobs (conservative defaults)
local HOT_THRESHOLD = tonumber(os.getenv("FAILED_LOGIN_HOT_THRESHOLD") or "10")   -- min. ZSET score
local TOP_K        = tonumber(os.getenv("FAILED_LOGIN_TOP_K") or "20")            -- only signal when within top-K
local SNAPSHOT_EVERY_SEC = tonumber(os.getenv("FAILED_LOGIN_SNAPSHOT_SEC") or "30") -- min interval for global top-N snapshot
local SNAPSHOT_TOPN = tonumber(os.getenv("FAILED_LOGIN_SNAPSHOT_TOPN") or "10")

local ZKEY = "ntc:top_failed_logins"

local function get_redis_client()
    local client = "default"
    local pool_name = os.getenv("CUSTOM_REDIS_POOL_NAME")
    if pool_name ~= nil and pool_name ~= "" then
        local err
        client, err = nauthilus_redis.get_redis_connection(pool_name)
        nauthilus_util.if_error_raise(err)
    end
    return client
end

local function maybe_snapshot_topN(client, now)
    -- Rate-limit via a simple timestamp key in Redis
    local gate_key = "ntc:feature:" .. N .. ":last_snapshot"
    local last = tonumber(nauthilus_redis.redis_get(client, gate_key) or "0")
    if last ~= nil and now - last < SNAPSHOT_EVERY_SEC then
        return
    end

    -- Pull small top-N for metrics; keep it cheap
    local members = nauthilus_redis.redis_zrevrange(client, ZKEY, 0, SNAPSHOT_TOPN - 1)
    if members and nauthilus_util.is_table(members) and #members > 0 then
        for i = 1, #members do
            local uname = members[i]
            local sc = nauthilus_redis.redis_zscore(client, ZKEY, uname)
            local score = tonumber(sc) or 0
            local rank = i - 1 -- i=1 -> rank 0
            nauthilus_prometheus.set_gauge(N .. "_top_score", score, { rank = tostring(rank), username = uname })
        end
        nauthilus_prometheus.set_gauge(N .. "_topn_size", #members, {})
    else
        nauthilus_prometheus.set_gauge(N .. "_topn_size", 0, {})
    end

    -- store gate, short TTL is fine
    nauthilus_redis.redis_set(client, gate_key, tostring(now), SNAPSHOT_EVERY_SEC)
end

function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    local username = request.username
    if not username or username == "" then
        -- No username context → nothing to signal
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    local client = get_redis_client()
    local now = os.time()

    -- Get score and rank for this username
    local score = nauthilus_redis.redis_zscore(client, ZKEY, username)
    local rank = nauthilus_redis.redis_zrevrank(client, ZKEY, username)

    local score_num = tonumber(score) or 0
    local rank_num = (rank ~= nil) and tonumber(rank) or -1

    -- Export basic metrics for this user
    nauthilus_prometheus.set_gauge(N .. "_user_score", score_num, { username = username })
    if rank_num >= 0 then
        nauthilus_prometheus.set_gauge(N .. "_user_rank", rank_num, { username = username })
    end

    -- Optional global snapshot (rate-limited), best-effort
    local ok, err = pcall(maybe_snapshot_topN, client, now)
    if not ok then
        local logs = { caller = N .. ".lua", level = "error", message = "snapshot failed", error = tostring(err) }
        nauthilus_util.print_result({ log_format = "json" }, logs)
    end

    -- Decide hotspot
    local is_hot = false
    if score_num >= HOT_THRESHOLD then
        if rank_num == -1 then
            -- Not in top list by rank (e.g., trimmed), still hot by score
            is_hot = true
        else
            is_hot = (rank_num >= 0 and rank_num < TOP_K)
        end
    end

    -- Get/prepare rt
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then rt = {} end

    if nauthilus_util.is_table(rt) then
        rt.failed_login_info = {
            username = username,
            new_count = score_num,
            rank = rank_num,
            recognized_account = (request.account ~= nil and request.account ~= ""),
        }
        if is_hot then
            rt.feature_failed_login_hotspot = true
            rt.failed_login_hot = true
        end
        nauthilus_context.context_set("rt", rt)
    end

    -- Custom logs for correlation
    nauthilus_builtin.custom_log_add("failed_login_username", username)
    nauthilus_builtin.custom_log_add("failed_login_count", tostring(score_num))
    if rank_num >= 0 then
        nauthilus_builtin.custom_log_add("failed_login_rank", tostring(rank_num))
    end

    if is_hot then
        nauthilus_prometheus.increment_counter(N .. "_count", { state = "hot" })
        return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
