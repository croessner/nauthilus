
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

-- testing_csv_loader.lua
-- Persist CSV-based login test data into the Go-backed nauthilus_cache so all Lua VMs share it.
-- This script is meant to run as an init plugin. It loads once at startup and can be reloaded on demand.

local nauthilus_util = require("nauthilus_util")
local nauthilus_cache = require("nauthilus_cache")

local M = {}

local KEY_PREFIX = "testing_csv:"
local KEY_LOADED = KEY_PREFIX .. "loaded"
local KEY_INDEX = KEY_PREFIX .. "index"         -- array of usernames
local KEY_USER_PREFIX = KEY_PREFIX .. "user:"   -- per-user record

local TESTING_CSV = nauthilus_util.getenv("TESTING_CSV", "client/logins.csv")

local function trim(s)
  if s == nil then return "" end
  return (tostring(s):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function parse_bool(s)
  s = trim(s):lower()
  return (s == "1" or s == "true" or s == "yes" or s == "y")
end

-- Simple CSV line parser (supports quotes and doubled quotes)
local function parse_csv_line(line)
  local res, field, i, in_quotes = {}, {}, 1, false
  while i <= #line do
    local c = line:sub(i, i)
    if in_quotes then
      if c == '"' then
        if line:sub(i+1, i+1) == '"' then
          field[#field+1] = '"'; i = i + 1
        else
          in_quotes = false
        end
      else
        field[#field+1] = c
      end
    else
      if c == '"' then
        in_quotes = true
      elseif c == ',' then
        res[#res+1] = table.concat(field); field = {}
      else
        field[#field+1] = c
      end
    end
    i = i + 1
  end
  res[#res+1] = table.concat(field)
  return res
end

local function read_all_lines(path)
  local f, err = io.open(path, "r")
  if not f then return nil, err end
  local lines = {}
  for l in f:lines() do lines[#lines+1] = l end
  f:close()
  return lines
end

-- Normalize headers to lowercase names
local function normalize_headers(headers)
  local out = {}
  for i, h in ipairs(headers) do
    out[i] = trim(h):lower()
  end
  return out
end

local function index_of(headers, name)
  name = name:lower()
  for i, h in ipairs(headers) do
    if h == name then return i end
  end
  return -1
end

-- Load CSV from disk and put into nauthilus_cache
local function load_csv_into_cache(csv_path)
  local lines, err = read_all_lines(csv_path)
  if not lines then
    return nil, string.format("cannot open CSV %s: %s", csv_path, err or "unknown")
  end
  if #lines == 0 then
    return nil, "CSV has no content"
  end

  local header = normalize_headers(parse_csv_line(lines[1]))
  local ix_username = index_of(header, "username")
  local ix_expected  = index_of(header, "expected_ok")
  if ix_username < 0 then return nil, "CSV must contain a username column" end
  if ix_expected < 0 then return nil, "CSV must contain an expected_ok column" end

  -- clear previous dataset
  if nauthilus_cache.cache_exists(KEY_INDEX) then
    local users = nauthilus_cache.cache_get(KEY_INDEX) or {}
    if type(users) == "table" then
      for _, u in ipairs(users) do
        nauthilus_cache.cache_delete(KEY_USER_PREFIX .. tostring(u))
      end
    end
    nauthilus_cache.cache_delete(KEY_INDEX)
  end

  local index = {}

  for li = 2, #lines do
    local line = lines[li]
    if trim(line) ~= "" then
      local cols = parse_csv_line(line)
      local rec = {}
      for i, h in ipairs(header) do
        rec[h] = trim(cols[i] or "")
      end
      local username = rec["username"] or ""
      if username ~= "" then
        local password = rec["password"] or ""
        local client_ip = rec["client_ip"] or ""
        local expected_ok = parse_bool(rec["expected_ok"]) -- defaults to false if invalid

        -- Collect all non-core fields as attributes
        local attrs = {}
        for k, v in pairs(rec) do
          if k ~= "username" and k ~= "password" and k ~= "client_ip" and k ~= "expected_ok" then
            attrs[k] = v
          end
        end

        local user_obj = {
          username = username,
          password = password,
          client_ip = client_ip,
          expected_ok = expected_ok,
          attrs = attrs,
        }

        nauthilus_cache.cache_set(KEY_USER_PREFIX .. username, user_obj, 0)
        index[#index+1] = username
      end
    end
  end

  nauthilus_cache.cache_set(KEY_INDEX, index, 0)
  nauthilus_cache.cache_set(KEY_LOADED, true, 0)

  return true
end

-- Public: allow manual (re)load
function M.init(opts)
  local path
    if type(opts) == "table" then
    path = opts.csv
  end
  if not path or trim(path) == "" then
      path = TESTING_CSV
  end
  return load_csv_into_cache(path)
end

-- Check login using cache content; returns ok(bool), attrs(table)
function M.check_login(username, password, client_ip)
  if not nauthilus_cache.cache_exists(KEY_LOADED) then
    -- Best effort: try to initialize from default path
    M.init({})
  end

  local key = KEY_USER_PREFIX .. trim(username)
  local rec = nauthilus_cache.cache_get(key)
  if type(rec) ~= "table" then
    return false, { reason = "user_not_found" }
  end

  local pass_ok = trim(password) == trim(rec.password or "")
  local ip_ok = true
  local configured_ip = trim(rec.client_ip or "")
  if configured_ip ~= "" then
    ip_ok = (trim(client_ip) == configured_ip)
  end

  local ok = pass_ok and ip_ok
  if rec.expected_ok ~= nil then
    ok = rec.expected_ok and true or false
  end

  local attrs = {}
  if type(rec.attrs) == "table" then
    for k, v in pairs(rec.attrs) do attrs[k] = v end
  end
  return ok, attrs
end

-- On load at startup, populate cache once unless already loaded
if not nauthilus_cache.cache_exists(KEY_LOADED) then
    local _ = M.init({ csv = TESTING_CSV })
end

-- Hook entrypoint called by Go after loading init scripts
-- See server/lualib/definitions.go: definitions.LuaFnRunHook ("nauthilus_run_hook")
function nauthilus_run_hook(request)
    local logging = request.logging
    local session = request.session
    local csv_path = TESTING_CSV
  local ok, err = M.init({ csv = csv_path })
  if not ok then
    return { ok = false, error = tostring(err), csv = csv_path }
  end

  local idx = nauthilus_cache.cache_get(KEY_INDEX)
  local count = 0
  if type(idx) == "table" then count = #idx end

  -- Log that everything is operational and CSV is loaded
  local result = {
    level = "SYSTEM",
    caller = "init/testing_csv_loader.lua",
    session = session,
    status = "success",
    message = string.format("CSV test data loaded (%d users) – system is ready.", count),
    csv = csv_path,
    users = count,
    loaded = nauthilus_cache.cache_exists(KEY_LOADED),
  }
    
  if logging and (logging.log_level == "debug" or logging.log_level == "info" or logging.log_level == "warn") then
    nauthilus_util.print_result(logging, result)
  end

  return { ok = true, loaded = nauthilus_cache.cache_exists(KEY_LOADED), users = count, csv = csv_path }
end

return M
