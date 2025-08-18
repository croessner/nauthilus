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

## Initialization Order

The initialization plugins are executed in a specific order:

1. `init.lua`: Sets up the basic infrastructure

This order ensures that dependencies are properly resolved, with basic infrastructure being set up before specialized components.

## Extending Initialization

To add custom initialization logic:

1. Create a new Lua file in this directory
2. Implement the `nauthilus_run_hook(logging)` function
3. Perform your initialization tasks within this function
4. Return a result table with status information

Your initialization plugin will be automatically executed during system startup.
