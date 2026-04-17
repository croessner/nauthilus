-- Example Lua backend for DB testing
-- This backend validates gopher-lua-libs db module availability.
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_backend_db.lua \
--                             --test-callback backend \
--                             --test-mock testdata/lua/backend_db_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_backend_result = require("nauthilus_backend_result")
local db = require("db")

local function new_backend_result(authenticated, user_found)
    local result = nauthilus_backend_result.new()
    result.authenticated = authenticated
    result.user_found = user_found

    return result
end

local function sql_quote(value)
    if value == nil then
        return ""
    end

    return tostring(value):gsub("'", "''")
end

function nauthilus_backend_verify_password(request)
    local username = nauthilus_context.context_get("username")

    if not username or username == "" then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local config = {
        shared = false,
        max_connections = 1,
        read_only = false,
    }

    local conn, err_open = db.open("mysql", "mock://nauthilus-test-db", config)
    if err_open ~= nil or conn == nil then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local escaped_username = sql_quote(username)
    local initial_display_name = "DB Test User Initial"
    local updated_display_name = "DB Test User Updated"

    local _, err_create = conn:exec("CREATE TABLE test_users (username TEXT, display_name TEXT);")
    if err_create ~= nil then
        conn:close()
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local insert_query = "INSERT INTO test_users (username, display_name) VALUES ('" ..
        escaped_username .. "', '" .. initial_display_name .. "');"
    local insert_result, err_insert = conn:exec(insert_query)
    if err_insert ~= nil or insert_result == nil then
        conn:close()
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local select_query = "SELECT display_name FROM test_users WHERE username = '" .. escaped_username .. "';"
    local selected_before_update, err_select_before = conn:query(select_query)
    if err_select_before ~= nil or selected_before_update == nil then
        conn:close()
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local before_row = selected_before_update.rows and selected_before_update.rows[1]
    if before_row == nil or before_row[1] ~= initial_display_name then
        conn:close()
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local update_query = "UPDATE test_users SET display_name = '" .. updated_display_name ..
        "' WHERE username = '" .. escaped_username .. "';"
    local update_result, err_update = conn:exec(update_query)
    if err_update ~= nil or update_result == nil then
        conn:close()
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local selected_after_update, err_select_after = conn:query(select_query)
    if err_select_after ~= nil or selected_after_update == nil then
        conn:close()
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local after_row = selected_after_update.rows and selected_after_update.rows[1]
    if after_row == nil or after_row[1] ~= updated_display_name then
        conn:close()
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local err_close = conn:close()
    if err_close ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local result = new_backend_result(false, true)
    result.account_field = username
    result.display_name = updated_display_name

    return nauthilus_builtin.BACKEND_RESULT_OK, result
end
