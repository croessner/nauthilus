nauthilus_policy.register_attribute({
    id = "lua.contract.registry_flag",
    description = "Test-only migration contract registry fact.",
    stage = "pre_auth",
    operations = {"authenticate"},
    type = "bool",
    category = "environment",
})
