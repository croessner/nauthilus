-- Runs haveibeenpwnd.lua with the nauthilus_send_mail_hash script that init/init.lua uploads, so a leaked password
-- reaches the notification branch exactly once.
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/actions/haveibeenpwnd.lua")
