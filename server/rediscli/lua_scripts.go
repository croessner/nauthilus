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
	// AuthPreflight performs a combined fetch of the mapped account name and a brute-force repeat check.
	// KEYS[1] - Hash key for username->account mapping (USER hash)
	// KEYS[2] - Hash key for brute-force network map
	// ARGV[1] - username
	// ARGV[2] - clientNet (can be empty)
	"AuthPreflight": `
local acc = redis.call('HGET', KEYS[1], ARGV[1])
if not acc then acc = '' end
local repeating = 0
if ARGV[2] and ARGV[2] ~= '' then
  if redis.call('HEXISTS', KEYS[2], ARGV[2]) == 1 then repeating = 1 end
end
return {acc, repeating}
`,
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

	// RWPAllowSet atomically checks whether a password hash is already in the allow-set or can be added
	// within the configured threshold. Returns 1 if RWP allowance applies, 0 otherwise.
	// KEYS[1] - The allow-set key (a Redis Set)
	// ARGV[1] - Threshold (max unique hashes)
	// ARGV[2] - TTL in seconds
	// ARGV[3] - Current password hash
	"RWPAllowSet": `
local key = KEYS[1]
local threshold = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local hash = ARGV[3]

if redis.call('SISMEMBER', key, hash) == 1 then
  redis.call('EXPIRE', key, ttl)
  return 1
end

local card = redis.call('SCARD', key)
if card < threshold then
  redis.call('SADD', key, hash)
  redis.call('EXPIRE', key, ttl)
  return 1
end

return 0
`,

	// ColdStartGraceSeed atomically sets a one-time cold-start grace key and seeds a per-password evidence key.
	// KEYS[1] - The cold-start key (SET NX EX ttl)
	// KEYS[2] - The seed key for the current password (SET NX EX ttl)
	// ARGV[1] - TTL in seconds
	"ColdStartGraceSeed": `
local c = redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1])
redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[1])
if c then return 1 else return 0 end
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
}
