# Shared Utility Modules for Nauthilus

This directory contains shared Lua utility modules for the Nauthilus authentication system. These modules provide common functions and utilities that can be used by other plugins throughout the system, promoting code reuse and consistency.

## Available Modules

### nauthilus_policy_facts.lua
Stores request-local policy facts, emits Lua-owned policy attributes, and optionally writes redaction-safe custom logs.

**Functions:**
- `set(namespace, key, value)`: Stores an internal fact under `policy_facts.<namespace>.<key>`
- `emit(namespace, key, value, details)`: Stores the fact and emits `lua.plugin.<namespace>.<key>`
- `emit_public(namespace, key, value, details)`: Emits the attribute, stores the fact, and writes a custom log
- `set_many(namespace, values)`: Stores multiple internal facts in one context update
- `emit_many(namespace, values)`: Stores and emits multiple internal policy attributes
- `emit_many_public(namespace, values)`: Stores, emits, and logs multiple public policy attributes
- `set_public(namespace, key, value)`: Compatibility alias for `emit_public`
- `set_many_public(namespace, values)`: Compatibility alias for `emit_many_public`
- `set_public_log(namespace, key, value)`: Writes only a `policy_fact_<namespace>_<key>` custom log
- `status_message(namespace, message)`: Sets the normal Nauthilus status message and emits a message attribute

**Usage:**
```lua
local policy_facts = require("nauthilus_policy_facts")

policy_facts.set("geoip", "guid", response.guid)
policy_facts.emit_public("geoip", "rejected", true, {
    status_message = "Policy violation",
})
policy_facts.status_message("geoip", "Policy violation")
```

Configure `auth.policy.registry_scripts` with `lua-plugins.d/policy/registry.lua` before using bundled emitted
attributes in policy rules. Use `emit_public` only for data that is already safe for normal custom logs. Use `emit` for
policy material that should not be copied to logs.

### nauthilus_geoip_bridge.lua
Copies native Go GeoIP runtime data from `plugin.environment.geoip` into the legacy Lua `rt.geoip_info` shape without
overwriting decisions already produced by `subject/geoip.lua`.

**Functions:**
- `native()`: Returns the native runtime table, or `nil` when the native plugin did not emit data.
- `attach()`: Merges native GeoIP and ASN fields into `rt.geoip_info`, refreshes `geoippolicyd_iso_codes_seen` when
  that legacy context value is missing, and returns the resulting `rt.geoip_info` table.

**Usage:**
```lua
local geoip_bridge = require("nauthilus_geoip_bridge")
local geoip_info = geoip_bridge.attach()
```

The bridge is intentionally decision-neutral. It preserves `guid`, `status`, and `current_country_code` from the
GeoIP policy service when they already exist, while adding native fields such as `asn`, `asn_org`, `asn_prefix`, and
`asn_registry` for logging, analytics, and future reputation scoring.

### nauthilus_util.lua
A comprehensive utility module that provides common functions used throughout the Nauthilus plugin system.

**Features:**
- **Table Operations**
  - `exists_in_table(tbl, element)`: Checks if an element exists in a table
  - `table_length(tbl)`: Calculates the length of a table
  
- **Type Checking**
  - `is_table(object)`: Checks if an object is a table
  - `is_string(object)`: Checks if an object is a string
  - `is_number(object)`: Checks if an object is a number
  
- **Error Handling**
  - `if_error_raise(err)`: Raises an error if the provided error string is not nil or empty
  
- **Data Conversion**
  - `toboolean(str)`: Converts a string to a boolean value
  
- **String Utilities**
  - `generate_random_string(length)`: Generates a random alphanumeric string of specified length
  
- **Network Utilities**
  - `is_routable_ip(ip)`: Checks if an IP address is routable on the internet (not private or reserved)
  
- **Logging**
  - `get_current_timestamp()`: Creates a timestamp string for logging
  - `print_result(logging, result, err_string)`: Formats and prints log messages in JSON or plain text

**Usage:**
Import the module in your Lua plugin:
```lua
local nauthilus_util = require("nauthilus_util")
```

Then use the functions as needed:
```lua
-- Check if an error occurred and raise it
nauthilus_util.if_error_raise(err)

-- Log a result
local result = {
    level = "info",
    message = "Operation completed successfully",
    count = 42
}
nauthilus_util.print_result({ log_format = "json" }, result)
```

## Creating New Shared Modules

To create a new shared utility module:

1. Create a new Lua file in this directory
2. Define your module as a table
3. Implement your utility functions
4. Return the module table at the end of the file

Example:
```lua
local my_module = {}

function my_module.my_function()
    -- Implementation
end

return my_module
```

Other plugins can then import and use your module:
```lua
local my_module = require("my_module")
my_module.my_function()
```

## Best Practices

When creating or modifying shared utility modules:

1. **Documentation**: Include detailed comments for each function explaining its purpose, parameters, and return values
2. **Error Handling**: Implement robust error handling to prevent failures from propagating
3. **Performance**: Optimize functions that will be called frequently
4. **Compatibility**: Ensure backward compatibility when modifying existing functions
5. **Testing**: Thoroughly test new functions to ensure they work correctly in all scenarios
