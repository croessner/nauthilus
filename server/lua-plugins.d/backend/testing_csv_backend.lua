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

-- testing_csv_backend.lua
-- Implements the official backend function using CSV data persisted in the Go-backed nauthilus_cache.

local nauthilus_util = require("nauthilus_util")

local nauthilus_cache = require("nauthilus_cache")

-- Ensure the backend result type is available in the VM
-- In production, this is registered by Go side; here we just use it.

local KEY_PREFIX = "testing_csv:"
local KEY_LOADED = KEY_PREFIX .. "loaded"
local KEY_USER_PREFIX = KEY_PREFIX .. "user:"

local function trim(s)
  if s == nil then return "" end
  return (tostring(s):gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Safe string extractor using nauthilus_util helpers
local function as_string(v)
  if nauthilus_util.is_string(v) then
    return v
  end
  if v == nil then return "" end
  return tostring(v)
end

-- Helper to load default CSV via init plugin if not already loaded
local function ensure_loaded()
  if nauthilus_cache.cache_exists(KEY_LOADED) then return true end
  -- try to require the init loader and run it
  local ok, initmod = pcall(require, "testing_csv_loader")
  if ok and type(initmod) == "table" and type(initmod.init) == "function" then
    local ok2, err = initmod.init({ csv = os.getenv("TESTING_CSV") or "client/logins.csv" })
    if not ok2 then
      return nil, err
    end
    return true
  end
  return nil, "testing_csv_loader not available or failed to load"
end

-- Official backend entrypoint expected by Nauthilus
function nauthilus_backend_verify_password(request)
  local _, err = ensure_loaded()
  if err ~= nil then
    -- Do not return an error without a backend result; construct a result object to avoid 500s.
    local b = nauthilus_backend_result.new()
    b:user_found(false)
    b:authenticated(false)
    b:attributes({ reason = "init_failed", error = tostring(err) })
    return 0, b
  end

  local b = nauthilus_backend_result.new()

  local username = trim(as_string(request.username))
  local password = trim(as_string(request.password))
  local client_ip = trim(as_string(request.client_ip))

  local rec = nauthilus_cache.cache_get(KEY_USER_PREFIX .. username)
  if not nauthilus_util.is_table(rec) then
    -- user not found
    if add_custom_log then add_custom_log("csv_auth", "user_not_found:" .. username) end
    b:user_found(false)
    b:authenticated(false)
    b:attributes({ reason = "user_not_found" })
    return nauthilus_builtin.BACKEND_RESULT_OK, b
  end

  -- default checks
  local pass_ok = password == trim(as_string(rec.password))
  local ip_ok = true
  local configured_ip = trim(as_string(rec.client_ip))
  if configured_ip ~= "" then
    ip_ok = (client_ip == configured_ip)
  end

  local ok = pass_ok and ip_ok
  if rec.expected_ok ~= nil then
    ok = (rec.expected_ok and true or false)
  end

  -- helpful diagnostics in server logs
  if add_custom_log then
    add_custom_log("csv_user", username)
    add_custom_log("csv_pass_ok", tostring(pass_ok))
    add_custom_log("csv_ip_ok", tostring(ip_ok))
    add_custom_log("csv_expected_ok", tostring(rec.expected_ok))
    add_custom_log("csv_final_ok", tostring(ok))
  end

  b:user_found(true)
  b:authenticated(ok)

  -- Provide an account field to integrate cleanly with core (use username)
  b:account_field("username")

  -- Attributes: pass through stored attrs and interesting request info
  local attrs = {}
  if nauthilus_util.is_table(rec.attrs) then
    for k, v in pairs(rec.attrs) do attrs[k] = v end
  end
  attrs.username = username
  attrs.client_ip_expected = configured_ip
  attrs.client_ip_seen = client_ip

  b:attributes(attrs)

  return 0, b
end
