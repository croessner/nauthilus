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

### learning-mode.lua
Implements a learning mode for the Nauthilus system to establish baseline behavior patterns before enabling full security measures.

**Features:**
- Collects authentication patterns during a learning period
- Establishes normal behavior baselines for users and the system
- Generates recommended security thresholds based on observed patterns
- Provides detailed reports on learning progress
- Transitions smoothly from learning to enforcement mode

**Usage:**
Access the plugin through HTTP requests with the following query parameters:
- `enabled=true|false|1|0`: Enables or disables learning mode

Example: `https://nauthilus-server/api/v1/custom/learning-mode?enabled=true`

### neural-feedback.lua
Collects feedback on neural network predictions to improve the accuracy of the machine learning models.

**Features:**
- Tracks true positives, false positives, true negatives, and false negatives
- Provides feedback mechanisms for administrators to correct misclassifications
- Calculates precision, recall, and F1 scores for model evaluation
- Stores feedback data for model retraining
- Generates performance reports for the neural network models

**Usage:**
Access the plugin through HTTP requests with the following query parameters:
- `is_brute_force=true|false|1|0`: Indicates whether the authentication attempt was a brute force attack
- `request_id=<id>`: The ID of the authentication request
- `client_ip=<ip>`: The client IP address
- `username=<username>`: The username being authenticated

Example: `https://nauthilus-server/api/v1/custom/neural-feedback?is_brute_force=true&request_id=12345&client_ip=192.168.1.1&username=testuser`

### train-neural-network.lua
Trains or retrains the neural network models used for anomaly detection based on collected data and feedback.

**Features:**
- Processes historical authentication data for training
- Incorporates feedback from the neural-feedback hook
- Supports incremental training to update existing models
- Provides detailed training metrics and progress reports
- Automatically deploys new models when training is complete

**Usage:**
Access the plugin through HTTP requests with the following query parameters:
- `epochs=<number>`: Number of training epochs (default: 50)
- `samples=<number>`: Maximum number of samples to use for training (default: 5000)

Example: `https://nauthilus-server/api/v1/custom/train-neural-network?epochs=100&samples=10000`
