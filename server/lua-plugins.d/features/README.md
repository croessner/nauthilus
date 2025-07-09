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

### neural.lua
Implements neural network-based anomaly detection for authentication requests to identify potentially malicious login attempts.

**Features:**
- Uses machine learning to detect unusual authentication patterns
- Analyzes multiple factors including time, location, device, and behavior
- Adapts to normal user behavior over time
- Assigns risk scores to authentication attempts
- Provides detailed explanations for high-risk assessments

**Usage:**
Configure the plugin through environment variables:
- `GEOIP_POLICY_URL`: URL of the GeoIP policy service endpoint

The plugin integrates with the GeoIP service to enhance anomaly detection with geographic information.

### neural_enhanced.lua
An enhanced version of the neural.lua plugin with additional features and improved accuracy.

**Features:**
- All features of the basic neural.lua plugin
- Support for more complex neural network architectures
- Integration with external threat intelligence feeds
- Real-time model updates without service interruption
- Advanced feature extraction for better anomaly detection
- Explainable AI components to understand decision factors

**Usage:**
The plugin runs automatically on each authentication attempt and uses Redis to store and retrieve metrics. No specific environment variables are required for this plugin, as it leverages the Redis connection established by the system.

This plugin requires more computational resources than the basic neural.lua plugin but provides higher accuracy and more detailed insights by analyzing patterns in authentication data stored in Redis.

### neural_remove_features.lua
Provides functionality to remove specific features from the canonical list in Redis for the neural network model.

**Features:**
- Removes specified features from the canonical feature list in Redis
- Helps maintain a clean and relevant feature set for the neural network
- Automatically resets the model to use the updated canonical features
- Publishes model update notifications to ensure all instances are aware of changes
- Returns detailed JSON responses for integration with admin interfaces

**Usage:**
Access the plugin through HTTP POST requests with a JSON payload specifying the features to remove:

```json
{
  "features": ["feature1", "feature2", "feature3"]
}
```

Example: `curl -X POST -H "Content-Type: application/json" -d '{"features": ["unused_feature", "noisy_feature"]}' http://localhost:8080/api/v1/lua/neural_remove_features`

### neural_reset.lua
Provides functionality to reset the neural network model to use only the canonical features from Redis.

**Features:**
- Resets the neural network model to use only the canonical features
- Fixes issues where the model's input size has grown too large
- Ensures all instances use a consistent set of features
- Provides detailed logging of the reset operation
- Returns JSON responses indicating success or failure

**Usage:**
Access the plugin through a simple HTTP POST request without any parameters:

Example: `curl -X POST http://localhost:8080/api/v1/lua/neural_reset`
