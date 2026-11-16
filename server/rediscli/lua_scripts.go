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

	// RecordTolerationEvent adds one toleration event and purges both sorted sets to the window.
	// Positive members are account names, so the positive set holds distinct accounts with a verified success.
	// Negative members are unique per failed attempt, so the negative set holds every counted failed login behind the
	// address. Events older than the window are purged; the negative set is capped to its newest entries, so a count
	// equal to the cap means "saturated". Readers count both sets with ZCOUNT over the window.
	// KEYS[1] - The positive sorted set
	// KEYS[2] - The negative sorted set
	// ARGV[1] - The current time in seconds
	// ARGV[2] - The window and expiration in seconds
	// ARGV[3] - The event kind: "positive" or "negative"
	// ARGV[4] - The member to add for the event
	// ARGV[5] - The maximum number of retained negative events
	// Returns: {positive, negative}
	"RecordTolerationEvent": `
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local cap = tonumber(ARGV[5])

if ARGV[3] == "positive" then
    redis.call("ZADD", KEYS[1], now, ARGV[4])
else
    redis.call("ZADD", KEYS[2], now, ARGV[4])
end

local cutoff = now - ttl
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", cutoff)
redis.call("ZREMRANGEBYSCORE", KEYS[2], "-inf", cutoff)

local negative = redis.call("ZCARD", KEYS[2])
if negative > cap then
    redis.call("ZREMRANGEBYRANK", KEYS[2], 0, negative - cap - 1)
    negative = cap
end

local positive = redis.call("ZCARD", KEYS[1])

if positive > 0 then
    redis.call("EXPIRE", KEYS[1], ttl)
end

if negative > 0 then
    redis.call("EXPIRE", KEYS[2], ttl)
end

return {positive, negative}
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

	// RWPSlidingWindowCheck performs a read-only check of the RWP sliding window.
	// It prunes expired entries and checks whether the password hash already exists or the window is below the limit,
	// but does NOT add the hash. The actual write is deferred to RWPSlidingWindowCommit.
	// KEYS[1] - The sorted set key
	// ARGV[1] - The password hash
	// ARGV[2] - Current timestamp (seconds)
	// ARGV[3] - TTL (seconds)
	// ARGV[4] - Max allowed unique hashes in the window
	"RWPSlidingWindowCheck": `
local key = KEYS[1]
local hash = ARGV[1]
local now = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local max = tonumber(ARGV[4])

-- Remove outdated entries (necessary for accurate cardinality)
redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. (now - ttl))

-- Check if hash already exists
local score = redis.call('ZSCORE', key, hash)

-- Only a previously confirmed failed hash receives an allowance
if score then
    return 1
end

return 0
`,

	// RWPSlidingWindowCommit writes the password hash into the RWP sliding window.
	// This must only be called after confirming that the password was actually wrong
	// (i.e., not rejected by an environment control before authentication).
	// KEYS[1] - The sorted set key
	// ARGV[1] - The password hash
	// ARGV[2] - Current timestamp (seconds)
	// ARGV[3] - TTL (seconds)
	// ARGV[4] - Max allowed unique hashes in the window
	"RWPSlidingWindowCommit": `
local key = KEYS[1]
local hash = ARGV[1]
local now = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local max = tonumber(ARGV[4])

-- Remove outdated entries
redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. (now - ttl))

-- Classify before mutation so concurrent failures cannot share a stale allowance.
local repeated = redis.call('ZSCORE', key, hash)

-- Add/update the current hash
redis.call('ZADD', key, now, hash)

-- If we exceed the max unique hashes, remove the oldest one
if redis.call('ZCARD', key) > max then
    redis.call('ZREMRANGEBYRANK', key, 0, 0)
end

redis.call('EXPIRE', key, ttl)

if repeated then
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

-- current_cnt and prev_cnt let diagnostics prove which increments fed a decision; readers ignore extra elements.
return {tostring(total), exceeded, tostring(limit), current_cnt, prev_cnt}
`,
}
