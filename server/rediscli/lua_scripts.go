// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package rediscli

// LuaScripts contains all the Lua scripts used in the application
var LuaScripts = map[string]string{
	// IncrementAndExpire increments a counter and sets an expiration time in a single atomic operation
	// KEYS[1] - The key to increment
	// ARGV[1] - The expiration time in seconds
	"IncrementAndExpire": `
local count = redis.call("INCR", KEYS[1])
redis.call("EXPIRE", KEYS[1], ARGV[1])
return count
`,

	// AddToSetAndExpire adds a value to a set and sets an expiration time in a single atomic operation
	// KEYS[1] - The set key
	// ARGV[1] - The value to add to the set
	// ARGV[2] - The expiration time in seconds
	"AddToSetAndExpire": `
local result = redis.call("SADD", KEYS[1], ARGV[1])
redis.call("EXPIRE", KEYS[1], ARGV[2])
return result
`,

	// ZAddCountAndExpire adds a member to a sorted set, counts the elements, and sets an expiration time
	// KEYS[1] - The sorted set key
	// KEYS[2] - The hash key to store the count
	// ARGV[1] - The score for the sorted set member
	// ARGV[2] - The member to add to the sorted set
	// ARGV[3] - The hash field to store the count
	// ARGV[4] - The expiration time in seconds
	"ZAddCountAndExpire": `
redis.call("ZADD", KEYS[1], ARGV[1], ARGV[2])
local count = redis.call("ZCOUNT", KEYS[1], "-inf", "+inf")
redis.call("EXPIRE", KEYS[1], ARGV[4])
redis.call("HSET", KEYS[2], ARGV[3], count)
redis.call("EXPIRE", KEYS[2], ARGV[4])
return count
`,

	// CalculateAdaptiveToleration calculates the adaptive toleration percentage based on positive authentication attempts
	// KEYS[1] - The hash key containing the counts
	// ARGV[1] - The minimum toleration percentage
	// ARGV[2] - The maximum toleration percentage
	// ARGV[3] - The scale factor
	// ARGV[4] - The static toleration percentage (fallback if adaptive is disabled)
	// ARGV[5] - Whether adaptive toleration is enabled (1 for true, 0 for false)
	"CalculateAdaptiveToleration": `
local positive = tonumber(redis.call("HGET", KEYS[1], "positive") or "0")
local negative = tonumber(redis.call("HGET", KEYS[1], "negative") or "0")
local min_percent = tonumber(ARGV[1])
local max_percent = tonumber(ARGV[2])
local scale_factor = tonumber(ARGV[3])
local static_percent = tonumber(ARGV[4])
local adaptive_enabled = tonumber(ARGV[5]) == 1

-- If adaptive toleration is disabled or there are no positive attempts, use static percentage
if not adaptive_enabled or positive == 0 then
    local max_negative = math.floor((static_percent * positive) / 100)
    return {static_percent, max_negative, positive, negative, 0}
end

-- Calculate adaptive percentage based on positive attempts and scale factor
local percent = min_percent
if positive > 0 then
    -- Calculate percentage between min and max based on positive attempts and scale factor
    local factor = math.min(1, math.log(positive + 1) / math.log(100) * scale_factor)
    percent = math.floor(min_percent + (max_percent - min_percent) * factor)

    -- Ensure percent is within bounds
    percent = math.max(min_percent, math.min(max_percent, percent))
end

-- Calculate maximum allowed negative attempts
local max_negative = math.floor((percent * positive) / 100)

-- Return the calculated percentage, max negative attempts, positive count, positive count, and factor
return {percent, max_negative, positive, negative, 1}
`,

	// AddToSetAndExpireLimit adds a hash to a set and sets an expiration time,
	// but only if the set hasn't reached the maximum number of entries.
	// If it has reached the limit, it only refreshes TTL if the hash is already present.
	// KEYS[1] - The set key
	// ARGV[1] - The hash to add
	// ARGV[2] - The expiration time in seconds
	// ARGV[3] - The maximum number of entries allowed in the set
	"AddToSetAndExpireLimit": `
local key = KEYS[1]
local hash = ARGV[1]
local ttl = tonumber(ARGV[2])
local max = tonumber(ARGV[3])

if redis.call('SCARD', key) >= max then
  if redis.call('SISMEMBER', key, hash) == 1 then
    redis.call('EXPIRE', key, ttl)
    return 1
  end
  return 0
end

redis.call('SADD', key, hash)
redis.call('EXPIRE', key, ttl)
return 1
`,

	// UnlockIfTokenMatches deletes the lock key only if the stored token matches the provided token
	// KEYS[1] - The lock key
	// ARGV[1] - The expected token
	"UnlockIfTokenMatches": `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`,

	// RWPSlidingWindow implements a sliding window for repeating-wrong-passwords using a sorted set.
	// KEYS[1] - The sorted set key
	// ARGV[1] - The password hash
	// ARGV[2] - Current timestamp (seconds)
	// ARGV[3] - TTL (seconds)
	// ARGV[4] - Max allowed unique hashes in the window
	"RWPSlidingWindow": `
local key = KEYS[1]
local hash = ARGV[1]
local now = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local max = tonumber(ARGV[4])

-- Remove outdated entries
redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. (now - ttl))

-- Check if hash already exists
local score = redis.call('ZSCORE', key, hash)
local card = redis.call('ZCARD', key)

-- Always add/update the current hash
redis.call('ZADD', key, now, hash)

-- If we exceed the max unique hashes, remove the oldest one
if redis.call('ZCARD', key) > max then
    redis.call('ZREMRANGEBYRANK', key, 0, 0)
end

redis.call('EXPIRE', key, ttl)

-- Return 1 if it was a repeat (existed before) or if we were below the limit
if score or card < max then
    return 1
end

return 0
`,
	// SlidingWindowCounter implements a sliding window counter for rate limiting with adaptive reputation scaling.
	// KEYS:
	//   [1] = current window key
	//   [2] = previous window key
	// ARGV:
	//   [1] = increment value (e.g. 1 to increase, 0 to only check)
	//   [2] = weight for previous window (float, 0.0 to 1.0)
	//   [3] = ttl for current window (seconds)
	//   [4] = base limit (number of failed requests - 1)
	//   [5] = adaptive enabled (1 or 0)
	//   [6] = min tolerate percent
	//   [7] = max tolerate percent
	//   [8] = scale factor
	//   [9] = static tolerate percent
	//   [10] = positive reputation counter
	//   [11] = rwp_floor (optional, 0 = disabled). When > 0 and the current counter is below
	//          this floor, the counter is raised to (rwp_floor - 1) before the normal increment.
	//          This compensates for attempts that were tolerated during the RWP grace period.
	// Returns:
	//   {tostring(total), exceeded, tostring(effective_limit)}
	"SlidingWindowCounter": `
local current_key = KEYS[1]
local prev_key = KEYS[2]

local increment = tonumber(ARGV[1])
local weight = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local base_limit = tonumber(ARGV[4] or "-1")

local adaptive_enabled = tonumber(ARGV[5] or "0") == 1
local min_percent = tonumber(ARGV[6] or "0")
local max_percent = tonumber(ARGV[7] or "0")
local scale_factor = tonumber(ARGV[8] or "1")
local static_percent = tonumber(ARGV[9] or "0")
local positive = tonumber(ARGV[10] or "0")
local rwp_floor = tonumber(ARGV[11] or "0")

local limit = base_limit

if positive > 0 then
    local percent = static_percent
    if adaptive_enabled then
        local factor = math.min(1, math.log(positive + 1) / math.log(100) * scale_factor)
        percent = math.floor(min_percent + (max_percent - min_percent) * factor)
        percent = math.max(min_percent, math.min(max_percent, percent))
    end
    limit = math.floor(base_limit * (1 + percent / 100))
end

local current_cnt = tonumber(redis.call("GET", current_key) or 0)
local is_new_key = (current_cnt == 0)

-- RWP catch-up: if the bucket is below the RWP floor, bring it up to (floor - 1)
-- so the subsequent normal +1 increment lands exactly at the floor value.
-- This compensates for the attempts that were tolerated during RWP grace.
if rwp_floor > 0 and current_cnt < rwp_floor then
    local delta = rwp_floor - 1 - current_cnt
    if delta > 0 then
        current_cnt = redis.call("INCRBY", current_key, delta)
    end
end

if increment > 0 then
    current_cnt = redis.call("INCRBY", current_key, increment)
end

-- Set expiry when the key was freshly created during this call
if is_new_key and current_cnt > 0 then
    redis.call("EXPIRE", current_key, ttl)
end

local prev_cnt = tonumber(redis.call("GET", prev_key) or 0)
local total = current_cnt + (prev_cnt * weight)

local exceeded = 0
if limit >= 0 and total > limit then
    exceeded = 1
end

return {tostring(total), exceeded, tostring(limit)}
`,

	// BanIndexListing reads all 16 sharded ZSET ban indexes in a single atomic call.
	// KEYS[1..16] = the 16 ZSET shard keys (prefix+bf:{bans}:0 .. prefix+bf:{bans}:F)
	// ARGV[1]     = minScore (e.g. 0 or now - maxBanTime)
	// ARGV[2]     = maxScore (e.g. +inf or now)
	// Returns a flat array: [member1, score1, member2, score2, ...]
	"BanIndexListing": `
local result = {}
for i = 1, #KEYS do
    local entries = redis.call('ZRANGEBYSCORE', KEYS[i], ARGV[1], ARGV[2], 'WITHSCORES')
    for j = 1, #entries, 2 do
        result[#result + 1] = entries[j]
        result[#result + 1] = entries[j + 1]
    end
end
return result
`,
}
