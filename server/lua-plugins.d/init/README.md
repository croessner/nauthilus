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

### init_neural.lua
Initializes the Redis Lua scripts needed for neural network operations and other atomic operations used throughout the system.

**Features:**
- Defines and uploads Redis Lua scripts for atomic operations:
  - `ZAddRemExpire`: Combines ZADD, ZREMRANGEBYSCORE, and EXPIRE operations
  - `HSetMultiExpire`: Combines multiple HSET operations and an EXPIRE operation
  - `SAddMultiExpire`: Combines multiple SADD operations and an EXPIRE operation
  - `ExistsHSetMultiExpire`: Checks if a key exists, and if not, performs multiple HSET operations and an EXPIRE operation
- Ensures that all neural network components have access to optimized Redis operations
- Provides logging of the initialization process

**Usage:**
This plugin runs automatically during system startup. It requires a working Redis connection to upload the scripts. The uploaded scripts are then available to all other plugins that need to perform atomic operations on Redis data structures.

These scripts are particularly important for the neural network components and security monitoring features, as they ensure that complex operations on Redis data structures are performed atomically, preventing race conditions and ensuring data integrity.

## Initialization Order

The initialization plugins are executed in a specific order:

1. `init.lua`: Sets up the basic infrastructure
2. `init_neural.lua`: Initializes neural network components

This order ensures that dependencies are properly resolved, with basic infrastructure being set up before specialized components.

## Extending Initialization

To add custom initialization logic:

1. Create a new Lua file in this directory
2. Implement the `nauthilus_run_hook(logging)` function
3. Perform your initialization tasks within this function
4. Return a result table with status information

Your initialization plugin will be automatically executed during system startup.
