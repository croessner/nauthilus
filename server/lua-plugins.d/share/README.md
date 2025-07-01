# Shared Utility Modules for Nauthilus

This directory contains shared Lua utility modules for the Nauthilus authentication system. These modules provide common functions and utilities that can be used by other plugins throughout the system, promoting code reuse and consistency.

## Available Modules

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
