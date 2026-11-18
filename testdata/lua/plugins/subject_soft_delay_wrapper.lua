-- Runs soft_delay.lua under the Redis layout probe against long-window and attack data seeded under the names
-- account_longwindow_metrics.lua and account_centric_monitoring.lua write.
local probe = require("redis_layout_probe")

probe.install()

dofile("server/lua-plugins.d/subject/soft_delay.lua")
