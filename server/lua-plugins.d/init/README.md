# Initialization Plugins for Nauthilus

This directory contains Lua initialization plugins for the Nauthilus authentication system. Initialization plugins are executed when the system starts up, setting up required components, registering services, and preparing the environment for other plugins.

## Available Plugins

### init.lua
The primary initialization plugin that sets up core components of the Nauthilus system.

**Features:**
- Registers Redis connection pools and custom scripts
- Sets up Prometheus metrics for monitoring different components
- Registers network connection targets for various services
- Configures external service endpoints based on environment variables
- Initializes monitoring for various plugins (analytics, haveibeenpwnd, telegram, etc.)

**Usage:**
This plugin runs automatically during system startup. You can configure it through environment variables:
- `CUSTOM_REDIS_POOL_NAME`: Name for a custom Redis connection pool
- `BLOCKLIST_SERVICE_ENDPOINT`: Endpoint for the blocklist service
- `GEOIP_POLICY_SERVICE_ENDPOINT`: Endpoint for the GeoIP policy service

The plugin sets up the necessary infrastructure for other plugins to function correctly, including:
- Redis scripts for email notifications
- Prometheus metrics for performance monitoring
- Network connection targets for external services

### extra-init.lua

Optional initialization plugin that bootstraps configuration for the Lua proxy backend and its metrics.

**Features:**

- Loads proxy backend settings from environment variables (with cached env lookups)
- Registers a psnet target for the upstream endpoint
- Creates Prometheus metrics for proxy backend HTTP calls

**Usage:**
This plugin is intended to be loaded in addition to `init.lua` via the multi-init configuration.

## Initialization Order

The initialization plugins are executed in a specific order:

1. `init.lua`: Sets up the basic infrastructure
2. `extra-init.lua`: Adds proxy backend configuration and metrics (optional)

This order ensures that dependencies are properly resolved, with basic infrastructure being set up before specialized components.

## Extending Initialization

To add custom initialization logic:

1. Create a new Lua file in this directory
2. Implement the `nauthilus_run_hook(logging)` function
3. Perform your initialization tasks within this function
4. Return a result table with status information

Your initialization plugin will be automatically executed during system startup.

## Proxy Backend Configuration (extra-init.lua)

If you use the Lua proxy backend (`server/lua-plugins.d/backend/proxy_backend.lua`), configure it via environment
variables and load `extra-init.lua` through the init script list:

```yaml
lua:
  config:
    init_script_paths:
      - "/etc/nauthilus/lua-plugins.d/init/init.lua"
      - "/etc/nauthilus/lua-plugins.d/init/extra-init.lua"
```

**Supported environment variables:**

- `PROXY_BACKEND_UPSTREAM_URL` (default: `http://127.0.0.1:9080`)
- `PROXY_BACKEND_AUTH_PATH` (default: `/api/v1/auth/json`)
- `PROXY_BACKEND_MFA_PATH` (default: `/api/v1/mfa-backchannel`)
- `PROXY_BACKEND_TIMEOUT` (default: `5s`)
- `PROXY_BACKEND_LIST_ACCOUNTS_USERNAME` (default: `list-accounts`)
- `PROXY_BACKEND_TYPE` (default: `lua`)
- `PROXY_BACKEND_NAME` (default: `default`)
- `PROXY_BACKEND_AUTH_TOKEN` (default: empty)
- `PROXY_BACKEND_BASIC_USER` (default: empty)
- `PROXY_BACKEND_BASIC_PASS` (default: empty)
