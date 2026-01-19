-- Copyright (C) 2025 Christian Rößner
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

-- dynamic-textmap-demo.lua
--
-- A minimal demo hook that serves text/plain content which changes over time, backed by Redis.
-- This can be used as a template to simulate dynamic maps (e.g., consumable by systems like Rspamd).
--
-- Behavior:
-- - GET: Returns a text/plain body representing a small map/list, with standard headers set
-- - HEAD: Returns the same headers (including Content-Length) but no body
-- - Content changes when the TTL window expires (default 60s). Version and Last-Modified update accordingly.
--
-- Configuration:
-- - Configure the same http_location twice (GET and HEAD) to enable both methods on one path.
-- - Optional env var: CUSTOM_REDIS_POOL_NAME selects a Redis pool (defaults to "default").
-- - Optional env var: TEXTMAP_DEMO_TTL_SECONDS controls TTL/rotation (defaults to 60 seconds).

local nauthilus_util = require("nauthilus_util")

local nauthilus_http_request = require("nauthilus_http_request")
local nauthilus_http_response = require("nauthilus_http_response")
local nauthilus_redis = require("nauthilus_redis")
local time = require("time")

local N = "dynamic-textmap-demo"

local KEY_CONTENT = "ntc:demo:textmap:content"
local KEY_VERSION = "ntc:demo:textmap:version"
local KEY_LASTMOD = "ntc:demo:textmap:last_modified"

local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")
local TEXTMAP_DEMO_TTL_SECONDS = tonumber(nauthilus_util.getenv("TEXTMAP_DEMO_TTL_SECONDS", "60")) or 60

local function rfc1123(ts)
    if ts == nil then
        return time.format(time.unix(), "Mon, 02 Jan 2006 15:04:05 MST", "UTC")
    end
    return time.format(ts, "Mon, 02 Jan 2006 15:04:05 MST", "UTC")
end

local function get_redis_pool()
    local pool = "default"
    if CUSTOM_REDIS_POOL ~= "default" then
        local err
        pool, err = nauthilus_redis.get_redis_connection(CUSTOM_REDIS_POOL)
        nauthilus_util.if_error_raise(err)
    end
    return pool
end

local function build_content(version, now)
    -- Example map format (plain text), lines starting with '#' are comments:
    -- Rspamd and similar tools can consume simple newline-delimited maps.
    local lines = {}
    table.insert(lines, "# dynamic-textmap-demo")
    table.insert(lines, "# version: " .. tostring(version))
    table.insert(lines, "# generated_at: " .. rfc1123(now))
    table.insert(lines, "# This list rotates every TTL window; use ETag/Last-Modified for caching.")
    table.insert(lines, "example.com")
    -- Change a couple of sample entries based on version to illustrate rotation
    local v = tonumber(version) or 0
    table.insert(lines, string.format("rotate-%d.example", (v % 10)))
    table.insert(lines, string.format("hash-%08x", (v * 2654435761) % 0xffffffff))
    return table.concat(lines, "\n") .. "\n"
end

local function ensure_content(pool, ttl)
    -- Try to fetch existing values using a single round-trip (pipeline of GET commands)
    local results, perr = nauthilus_redis.redis_pipeline(pool, "read", {
        {"get", KEY_CONTENT},
        {"get", KEY_VERSION},
        {"get", KEY_LASTMOD},
    })
    if perr then
        -- Fallback to non-pipelined GETs if pipeline isn't available
        local content = nauthilus_redis.redis_get(pool, KEY_CONTENT)
        local version = nauthilus_redis.redis_get(pool, KEY_VERSION)
        local lastmod = nauthilus_redis.redis_get(pool, KEY_LASTMOD)
        if content and version and lastmod then
            return content, tonumber(version) or 0, tonumber(lastmod) or time.unix()
        end
        results = nil
    end

    local content, version, lastmod
    if results and results[1] and results[1].ok and results[2] and results[2].ok and results[3] and results[3].ok then
        content = results[1].value
        version = results[2].value
        lastmod = results[3].value
        if content and version and lastmod then
            return content, tonumber(version) or 0, tonumber(lastmod) or time.unix()
        end
    end

    -- (Re)build content when missing/expired
    -- First, get the new version using a single write pipeline
    local incrRes, ierr = nauthilus_redis.redis_pipeline(pool, "write", {
        {"incr", KEY_VERSION},
    })
    local new_version
    if ierr or not incrRes or not incrRes[1] or not incrRes[1].ok then
        -- Fallback: if INCR not available, try to read current version and add 1
        local current = tonumber(nauthilus_redis.redis_get(pool, KEY_VERSION) or "0") or 0
        new_version = current + 1
        nauthilus_redis.redis_set(pool, KEY_VERSION, tostring(new_version))
    else
        new_version = tonumber(incrRes[1].value) or 1
    end

    local now = time.unix()
    local new_content = build_content(new_version, now)

    -- Set keys with TTL so content rotates (single pipeline write)
    local _, werr = nauthilus_redis.redis_pipeline(pool, "write", {
        {"set", KEY_CONTENT, new_content, ttl},
        {"set", KEY_LASTMOD, tostring(now), ttl},
        {"set", KEY_VERSION, tostring(new_version)},
    })
    if werr then
        -- As a minimal fallback, try non-pipelined sets
        nauthilus_redis.redis_set(pool, KEY_CONTENT, new_content, ttl)
        nauthilus_redis.redis_set(pool, KEY_LASTMOD, tostring(now), ttl)
        nauthilus_redis.redis_set(pool, KEY_VERSION, tostring(new_version))
    end

    return new_content, new_version, now
end

function nauthilus_run_hook(logging, session)
    local result = {
        level = "info",
        caller = N .. ".lua",
        session = session,
    }

    local method = nauthilus_http_request.get_http_method()
    local path = nauthilus_http_request.get_http_path()

    local ttl = tonumber(os.getenv("TEXTMAP_DEMO_TTL_SECONDS") or "60")
    if ttl < 1 then ttl = 60 end

    local pool = get_redis_pool()

    local content, version, lastmod_ts = ensure_content(pool, ttl)
    local content_length = tostring(#content)

    -- Common headers
    nauthilus_http_response.set_http_response_header("Cache-Control", "no-cache")
    nauthilus_http_response.set_http_response_header("ETag", string.format("W/\"v%d-%s\"", version, content_length))
    nauthilus_http_response.set_http_response_header("Last-Modified", rfc1123(lastmod_ts))

    if method == "HEAD" then
        nauthilus_http_response.string(nauthilus_http_response.STATUS_OK, "")

        result.status = "success"
        result.message = "HEAD response sent (no body)"
        result.path = path
        result.version = version

        if logging.log_level == "debug" or logging.log_level == "info" then
            nauthilus_util.print_result(logging, result)
        end
        return nil
    elseif method == "GET" then
        nauthilus_http_response.string(nauthilus_http_response.STATUS_OK, content)

        result.status = "success"
        result.message = "GET response sent"
        result.path = path
        result.version = version

        if logging.log_level == "debug" or logging.log_level == "info" then
            nauthilus_util.print_result(logging, result)
        end
        return nil
    else
        nauthilus_http_response.set_http_response_header("Allow", "GET, HEAD")
        nauthilus_http_response.string(nauthilus_http_response.STATUS_METHOD_NOT_ALLOWED, "Method Not Allowed\n")

        result.status = "error"
        result.message = "Unsupported method"
        result.method = method

        if logging.log_level == "debug" or logging.log_level == "info" then
            nauthilus_util.print_result(logging, result)
        end
        return nil
    end
end
