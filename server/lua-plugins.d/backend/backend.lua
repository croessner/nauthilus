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

--[[
    MySQL demo table with full Lua backend examples:

    CREATE TABLE `nauthilus` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `username` varchar(255) NOT NULL,
      `password` varchar(255) NOT NULL,
      `account` varchar(255) NOT NULL,
      `totp_secret` varchar(255) DEFAULT NULL,
      `uniqueid` varchar(255) NOT NULL,
      `display_name` varchar(255) DEFAULT NULL,
      PRIMARY KEY (`id`),
      UNIQUE KEY `UsernameIdx` (`username`),
      UNIQUE KEY `AccountIdx` (`account`),
      UNIQUE KEY `UniqueidIdx` (`uniqueid`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
]]--

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_password")
local nauthilus_password = require("nauthilus_password")

dynamic_loader("nauthilus_gll_db")
local db = require("db")

local config = {
    shared = true,
    max_connections = 100,
    read_only = false,
}

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local mysql, err_open = db.open("mysql", "nauthilus:nauthilus@tcp(127.0.0.1)/nauthilus", config)
    nauthilus_util.if_error_raise(err_open)

    local result, err_query = mysql:query(
        "SELECT account, password, totp_secret, uniqueid, display_name FROM nauthilus WHERE username = \"" .. request.username .. "\" OR account = \"" .. request.username .. "\";")
    nauthilus_util.if_error_raise(err_query)

    -- We do not want to return all results to each protocol
    local filter_result_value = function(key)
        if request.protocol ~= "ory-hydra" then
            if key == "totp_secret" then
                return true
            elseif key == "uniqueid" then
                return true
            elseif key == "display_name" then
                return true
            end
        end

        return false
    end

    local attributes = {}

    for _, row in pairs(result.rows) do
        for id, name in pairs(result.columns) do
            if name == "password" then
                if not request.no_auth then
                    -- The example assumes crypted passwords in the database.
                    local match, err = nauthilus_password.compare_passwords(row[id], request.password)
                    nauthilus_util.if_error_raise(err)

                    b:authenticated(match)
                end
            else
                local skip = filter_result_value(name)

                if not skip then
                    if name == "account" then
                        b:account_field("account")
                        b:user_found(true)
                    end

                    if name == "totp_secret" and row[id] ~= "" then
                        b:totp_secret_field("totp_secret")
                    end

                    if name == "uniqueid" and row[id] ~= "" then
                        b:unique_user_id_field("uniqueid")
                    end

                    if name == "display_name" and row[id] ~= "" then
                        b:display_name_field("display_name")
                    end

                    attributes[name] = row[id]
                end
            end
        end
    end

    -- Add additional attributes...
    attributes.example = "demo"

    b:attributes(attributes)

    nauthilus_builtin.custom_log_add("backend_lua", "success")

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end

function nauthilus_backend_list_accounts()
    local mysql, err_open = db.open("mysql", "nauthilus:nauthilus@tcp(127.0.0.1)/nauthilus", config)
    nauthilus_util.if_error_raise(err_open)

    local result, err_query = mysql:query("SELECT account FROM nauthilus LIMIT 100;")
    nauthilus_util.if_error_raise(err_query)

    local accounts = {}

    for _, row in pairs(result.rows) do
        for id, _ in pairs(result.columns) do
            table.insert(accounts, row[id])
        end
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, accounts
end

function nauthilus_backend_add_totp(request)
    local mysql, err_open = db.open("mysql", "nauthilus:nauthilus@tcp(127.0.0.1)/nauthilus", config)
    nauthilus_util.if_error_raise(err_open)

    local _, err_exec = mysql:exec("UPDATE nauthilus SET totp_secret=\"" .. request.totp_secret .. "\" WHERE username=\"" .. request.username .. "\";")
    nauthilus_util.if_error_raise(err_exec)

    return nauthilus_builtin.BACKEND_RESULT_OK
end
