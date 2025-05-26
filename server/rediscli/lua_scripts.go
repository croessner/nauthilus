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
}
