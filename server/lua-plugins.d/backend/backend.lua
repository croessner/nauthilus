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

local db = require("db")
local pw = require("nauthilus_util")

local config = {
    shared = true,
    max_connections = 100,
    read_only = false,
}

function nauthilus_backend_verify_password(request)
    local b = backend_result.new()

    local mysql, err_open = db.open("mysql", "nauthilus:nauthilus@tcp(127.0.0.1)/nauthilus", config)
    if err_open then
        error(err_open)
    end

    local result, err_query = mysql:query(
        "SELECT account, password, totp_secret, uniqueid, display_name FROM nauthilus WHERE username = \"" .. request.username .. "\" OR account = \"" .. request.username .. "\";")
    if err_query then
        error(err_query)
    end

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
                    local match, err = pw.compare_passwords(row[id], request.password)
                    if err then
                        error(err)
                    end

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

    nauthilus.custom_log_add("backend_lua", "success")

    return nauthilus.BACKEND_RESULT_OK, b
end

function nauthilus_backend_list_accounts()
    local mysql, err_open = db.open("mysql", "nauthilus:nauthilus@tcp(127.0.0.1)/nauthilus", config)
    if err_open then
        error(err_open)
    end

    local result, err_query = mysql:query("SELECT account FROM nauthilus LIMIT 100;")
    if err_query then
        error(err_query)
    end

    local accounts = {}

    for _, row in pairs(result.rows) do
        for id, _ in pairs(result.columns) do
            table.insert(accounts, row[id])
        end
    end

    return nauthilus.BACKEND_RESULT_OK, accounts
end

function nauthilus_backend_add_totp(request)
    local mysql, err_open = db.open("mysql", "nauthilus:nauthilus@tcp(127.0.0.1)/nauthilus", config)
    if err_open then
        error(err_open)
    end

    local _, err_exec = mysql:exec("UPDATE nauthilus SET totp_secret=\"" .. request.totp_secret .. "\" WHERE username=\"" .. request.username .. "\";")
    if err_exec then
        error(err_exec)
    end

    return nauthilus.BACKEND_RESULT_OK
end
