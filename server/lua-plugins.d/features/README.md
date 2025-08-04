# Feature Plugins for Nauthilus

This directory contains Lua feature plugins for the Nauthilus authentication system. Feature plugins extend the core functionality of Nauthilus by adding new capabilities, integrations, or advanced security features.

## Available Plugins

### blocklist.lua
Implements IP and username blocklisting functionality to prevent authentication attempts from known malicious sources.

**Features:**
- Checks authentication requests against configurable blocklists
- Supports IP address, IP range, and username blocklisting
- Integrates with external blocklist sources
- Provides automatic updates of blocklists
- Logs detailed information about blocked authentication attempts

**Usage:**
Configure the plugin through environment variables:
- `BLOCKLIST_URL`: URL of the blocklist service endpoint

You can also manually add entries to the blocklist using the Nauthilus API.

### global_pattern_monitoring.lua
Monitors global authentication patterns across the entire system to detect anomalies and potential security threats.

**Features:**
- Tracks authentication metrics in multiple time windows (1min, 5min, 15min, 1hour)
- Monitors unique IPs, unique usernames, and authentication attempts
- Calculates key metrics like attempts per IP, attempts per user, and IPs per user
- Stores current and historical metrics for trend analysis
- Provides detailed logging of global authentication patterns

**Usage:**
The plugin runs automatically on each authentication attempt. It stores metrics in Redis using keys with the prefix `ntc:multilayer:global:`. You can optionally configure a custom Redis pool using the `CUSTOM_REDIS_POOL_NAME` environment variable.

The metrics collected by this plugin are used by other components like the dynamic_response.lua action plugin to detect and respond to suspicious activity.
