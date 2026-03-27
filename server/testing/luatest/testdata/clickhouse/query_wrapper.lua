local source = debug.getinfo(1, "S").source
local script_path = source:sub(2)
local script_dir = script_path:match("(.*/)")
if script_dir:sub(1, 1) ~= "/" then
    script_dir = "/" .. script_dir
end

dofile(script_dir .. "../../../../lua-plugins.d/hooks/clickhouse-query.lua")
