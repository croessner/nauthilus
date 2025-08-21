# Hook Plugins for Nauthilus

This directory contains Lua hook plugins for the Nauthilus authentication system. Hook plugins are executed at specific points in the system's lifecycle or in response to specific events, allowing for custom processing, administrative functions, and integration with external systems.

## Available Plugins

### distributed-brute-force-admin.lua
Provides administrative functions for managing distributed brute force protection measures through an HTTP API.

**Features:**
- Retrieves security metrics from Redis for monitoring
- Allows administrators to reset protection measures
- Provides account-specific management functions
- Returns structured JSON responses for integration with admin interfaces
- Supports multiple actions through HTTP query parameters

**Usage:**
Access the plugin through HTTP requests with the following query parameters:
- `action=get_metrics`: Retrieves current security metrics
- `action=reset_protection`: Resets all protection measures
- `action=reset_account&username=<username>`: Resets protection for a specific account

Example: `https://nauthilus-server/api/v1/custom/distributed-brute-force-admin?action=get_metrics`

### distributed-brute-force-test.lua
A testing tool for simulating distributed brute force attacks to verify that protection measures are working correctly.

**Features:**
- Simulates authentication attempts from multiple IPs
- Creates controlled test scenarios for security testing
- Configurable attack patterns and intensity
- Provides detailed logging of test activities
- Includes detection verification

**Usage:**
Access the plugin through HTTP requests with the following query parameters:
- `action=simulate_attack`: Simulates a distributed attack
- `action=check_detection`: Checks if an attack was detected
- `action=run_test`: Runs a complete test (simulation + detection check)
- `username=<username>`: Specifies the target account for the simulation
- `num_ips=<number>`: Sets the number of IPs to use in the attack (default: 20)
- `country_code=<code>`: Optional country code for regional attack simulation

Example: `https://nauthilus-server/api/v1/custom/distributed-brute-force-test?action=run_test&username=testuser&num_ips=30&country_code=RU`

### dovecot-session-cleaner.lua
Manages Dovecot authentication sessions, cleaning up expired sessions and maintaining session data.

**Features:**
- Periodically cleans up expired Dovecot authentication sessions
- Maintains session data in Redis with appropriate TTLs
- Provides statistics on active and expired sessions
- Optimizes Redis memory usage by removing unnecessary data
- Configurable Redis pool

**Usage:**
The plugin runs automatically when triggered by Dovecot session events. You can configure it through environment variables:
- `CUSTOM_REDIS_POOL_NAME`: The name of the Redis pool to use (defaults to "default" if not specified)

## Configuring Hooks in nauthilus.yml

To use the hooks in this directory, you need to configure them in your nauthilus.yml configuration file. Hooks are configured in the `lua.custom_hooks` section of the configuration file.

### Configuration Structure

Each hook requires the following configuration:

```yaml
lua:
  custom_hooks:
    - http_location: "hook-name"      # The URL path for the hook (relative to /api/v1/custom/)
      http_method: "HTTP_METHOD"      # The HTTP method (GET, POST, PUT, DELETE, PATCH)
      script_path: "/path/to/hook.lua" # Full path to the Lua script
      roles: ["role1", "role2"]       # Optional: List of roles that can access this hook when JWT auth is enabled
```

### Example Configuration

Here's an example configuration for the hooks described in this README:

```yaml
lua:
  custom_hooks:
    - http_location: "distributed-brute-force-admin"
      http_method: "POST"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/distributed-brute-force-admin.lua"
      roles: ["admin", "security"]

    - http_location: "distributed-brute-force-test"
      http_method: "POST"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/distributed-brute-force-test.lua"
      roles: ["admin", "security"]
```

### Access Control with JWT Authentication

When JWT authentication is enabled in Nauthilus, you can restrict access to hooks based on user roles:

1. Define the required roles in the `roles` array for each hook
2. Users must have at least one of the specified roles in their JWT token to access the hook
3. If no roles are specified, any authenticated user can access the hook
4. If JWT authentication is not enabled, role restrictions are ignored

### Enabling/Disabling All Custom Hooks

You can disable all custom hooks by setting `custom_hooks: false` in the `server.disabled_endpoints` section:

```yaml
server:
  disabled_endpoints:
    custom_hooks: true  # Disables all custom hooks
```
