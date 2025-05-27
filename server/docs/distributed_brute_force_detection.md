# Distributed Brute Force Attack Detection and Mitigation

## Overview

This document outlines a comprehensive approach to detecting and mitigating distributed brute force attacks that bypass traditional IP-based brute force protection mechanisms. It addresses scenarios where attackers use a large number of unique IP addresses (potentially millions) with a small number of login attempts per IP to avoid triggering traditional brute force detection systems.

## Problem Statement

Traditional brute force protection systems typically track failed login attempts by IP address and block IPs that exceed a certain threshold within a specified time period. However, sophisticated attackers can bypass this protection by:

1. Using a large pool of unique IP addresses (e.g., botnets with millions of compromised devices)
2. Limiting the number of attempts per IP to stay below detection thresholds (e.g., 1-2 attempts per IP)
3. Targeting specific accounts with distributed attempts across many IPs

This distributed approach allows attackers to conduct large-scale brute force attacks while evading traditional IP-based protection mechanisms.

## Current System Limitations

Nauthilus currently implements several brute force protection mechanisms:

1. **Static IP-based Protection**: Blocks IP addresses that exceed a configured threshold of failed attempts
2. **Adaptive Toleration**: Dynamically adjusts tolerance thresholds based on successful authentication volume
3. **Neural Network Detection**: Uses machine learning to identify potential brute force attacks based on various features

While these mechanisms are effective against traditional brute force attacks, they have limitations when facing distributed attacks:

- **IP-based Protection**: Ineffective when each IP makes only 1-2 attempts
- **Adaptive Toleration**: Still primarily focused on individual IP behavior
- **Neural Network**: Currently not optimized to detect patterns across multiple IPs

## Enhanced Detection Strategy

To effectively detect and mitigate distributed brute force attacks, we propose a multi-layered approach that combines:

1. **Global Pattern Recognition**: Detecting abnormal authentication patterns across the entire system
2. **Account-Centric Monitoring**: Focusing on unusual activity targeting specific accounts
3. **Real-time Anomaly Detection**: Using machine learning to identify deviations from normal behavior
4. **Dynamic Response Mechanisms**: Implementing adaptive countermeasures based on threat severity

### 1. Global Pattern Recognition

#### Implementation with Lua and Redis

```lua
-- Example Lua script for global pattern monitoring
dynamic_loader("nauthilus_redis")
local redis = require("nauthilus_redis")

-- Track global authentication metrics in sliding windows
function track_global_metrics(event)
    local timestamp = os.time()
    local window_sizes = {60, 300, 900, 3600} -- 1min, 5min, 15min, 1hour

    for _, window in ipairs(window_sizes) do
        local key = "nauthilus:global:auth_attempts:" .. window
        redis.call("ZADD", key, timestamp, event.request_id)
        redis.call("ZREMRANGEBYSCORE", key, 0, timestamp - window)
        redis.call("EXPIRE", key, window * 2)
    end

    -- Track unique IPs
    local ip_key = "nauthilus:global:unique_ips:" .. window
    redis.call("ZADD", ip_key, timestamp, event.client_ip)
    redis.call("ZREMRANGEBYSCORE", ip_key, 0, timestamp - window)
    redis.call("EXPIRE", ip_key, window * 2)

    -- Track unique usernames
    local user_key = "nauthilus:global:unique_users:" .. window
    redis.call("ZADD", user_key, timestamp, event.username)
    redis.call("ZREMRANGEBYSCORE", user_key, 0, timestamp - window)
    redis.call("EXPIRE", user_key, window * 2)
end

-- Detect abnormal global patterns
function detect_global_anomalies()
    local timestamp = os.time()
    local window = 3600 -- 1 hour window

    local key = "nauthilus:global:auth_attempts:" .. window
    local ip_key = "nauthilus:global:unique_ips:" .. window
    local user_key = "nauthilus:global:unique_users:" .. window

    local attempts = redis.call("ZCOUNT", key, timestamp - window, timestamp)
    local unique_ips = redis.call("ZCOUNT", ip_key, timestamp - window, timestamp)
    local unique_users = redis.call("ZCOUNT", user_key, timestamp - window, timestamp)

    -- Calculate metrics
    local attempts_per_ip = attempts / math.max(unique_ips, 1)
    local attempts_per_user = attempts / math.max(unique_users, 1)
    local ips_per_user = unique_ips / math.max(unique_users, 1)

    -- Store historical averages for comparison
    update_historical_averages(attempts_per_ip, attempts_per_user, ips_per_user)

    -- Compare with historical patterns
    local is_anomalous = compare_with_historical_patterns(attempts_per_ip, attempts_per_user, ips_per_user)

    return is_anomalous, {
        attempts = attempts,
        unique_ips = unique_ips,
        unique_users = unique_users,
        attempts_per_ip = attempts_per_ip,
        attempts_per_user = attempts_per_user,
        ips_per_user = ips_per_user
    }
end
```

### 2. Account-Centric Monitoring

#### Implementation with Lua and Redis

```lua
-- Example Lua script for account-centric monitoring
function monitor_account_activity(username)
    local timestamp = os.time()
    local window = 3600 -- 1 hour window

    -- Get unique IPs that attempted to access this account
    local ip_key = "nauthilus:account:" .. username .. ":ips:" .. window
    local unique_ips = redis.call("ZCOUNT", ip_key, timestamp - window, timestamp)

    -- Get failed attempts for this account
    local fail_key = "nauthilus:account:" .. username .. ":fails:" .. window
    local failed_attempts = redis.call("ZCOUNT", fail_key, timestamp - window, timestamp)

    -- Calculate the ratio of unique IPs to failed attempts
    local ip_to_fail_ratio = unique_ips / math.max(failed_attempts, 1)

    -- If many unique IPs are trying to access a single account with few attempts per IP,
    -- this could indicate a distributed brute force attack
    if unique_ips > 10 and ip_to_fail_ratio > 0.8 then
        return true, {
            username = username,
            unique_ips = unique_ips,
            failed_attempts = failed_attempts,
            ip_to_fail_ratio = ip_to_fail_ratio
        }
    end

    return false, nil
end
```

### 3. Real-time Anomaly Detection with Neural Network

The existing neural network can be enhanced to detect distributed brute force attacks by:

1. **Adding Global Features**: Incorporate system-wide metrics into the neural network
2. **Temporal Pattern Analysis**: Analyze patterns over time to detect unusual spikes
3. **Account-Specific Features**: Include features related to account targeting patterns

#### Enhanced Features for Neural Network

```go
package ml

// Additional features for the neural network
type EnhancedLoginFeatures struct {
    // Existing features
    TimeBetweenAttempts    float64
    FailedAttemptsLastHour float64
    DifferentUsernames     float64
    DifferentPasswords     float64
    TimeOfDay              float64
    SuspiciousNetwork      float64

    // New global features
    GlobalAuthRate         float64 // Authentication attempts per minute system-wide
    GlobalUniqueIPRate     float64 // New unique IPs per minute system-wide
    GlobalIPUserRatio      float64 // Ratio of unique IPs to unique usernames

    // New account-specific features
    AccountTargetingScore  float64 // How targeted is this account compared to others
    AccountUniqueIPRate    float64 // Rate of unique IPs attempting to access this account
    AccountFailRatio       float64 // Ratio of failed to successful attempts for this account

    // Additional features
    AdditionalFeatures     map[string]any
}
```

### 4. Dynamic Response Mechanisms

Based on the detected threat level, implement dynamic response mechanisms:

1. **Progressive Challenge Levels**: Increase authentication challenges based on threat level
2. **Temporary Global Rate Limiting**: Implement system-wide rate limiting during attack periods
3. **Adaptive IP Reputation System**: Maintain a dynamic reputation system for IP addresses
4. **Geographic-based Filtering**: Temporarily restrict authentication from suspicious regions

#### Implementation with Lua

```lua
-- Example Lua script for dynamic response
function apply_dynamic_response(threat_level, metrics)
    if threat_level >= 0.9 then
        -- Severe threat: Implement strict measures
        enable_global_captcha()
        enable_global_rate_limiting()
        enable_geographic_filtering(metrics.suspicious_regions)
        increase_ml_sensitivity()
    elseif threat_level >= 0.7 then
        -- High threat: Implement moderate measures
        enable_targeted_captcha(metrics.targeted_accounts)
        enable_targeted_rate_limiting(metrics.suspicious_ips)
    elseif threat_level >= 0.5 then
        -- Moderate threat: Implement light measures
        enable_monitoring_mode()
        notify_administrators(metrics)
    end

    -- Log the response
    log_threat_response(threat_level, metrics)
end
```

## Integration with Existing Systems

### Lua Script Integration

1. **Feature Scripts**: Implement global pattern recognition as a Lua feature
2. **Filter Scripts**: Implement account-centric monitoring as a Lua filter
3. **Post-Action Scripts**: Implement dynamic response mechanisms as post-actions
4. **Custom Hooks**: Create custom endpoints for monitoring and administration

### Redis Integration

1. **Sliding Window Counters**: Use Redis sorted sets for efficient sliding window counters
2. **Distributed State**: Store global state information in Redis for cluster-wide visibility
3. **Historical Patterns**: Maintain historical pattern data in Redis for anomaly detection

### Neural Network Integration

1. **Feature Enhancement**: Add new features to the existing neural network
2. **Model Retraining**: Retrain the model with new features and labeled attack data
3. **Feedback Loop**: Implement a feedback loop to continuously improve detection accuracy

## Implementation Plan

### Phase 1: Monitoring and Data Collection

1. ✅ Implement global pattern monitoring with Lua and Redis
   - Implemented in `server/lua-plugins.d/features/global_pattern_monitoring.lua`
   - Tracks authentication attempts, unique IPs, and unique usernames in sliding windows
   - Stores metrics for analysis and anomaly detection
2. ✅ Collect baseline data for normal authentication patterns
   - Historical metrics are stored in Redis with hourly granularity
   - Metrics include attempts, unique IPs, unique users, and derived ratios
3. ✅ Develop visualization tools for monitoring global authentication metrics
   - Implemented in `server/bruteforce/ml/distributed_brute_force_metrics.go`
   - Exposes Redis metrics as Prometheus metrics
   - Created Grafana dashboard in `contrib/grafana/nauthilus-distributed-brute-force.json`
   - Metrics include authentication attempts, unique IPs, unique users, and derived ratios

### Phase 2: Detection Mechanisms

1. ✅ Implement account-centric monitoring
   - Implemented in `server/lua-plugins.d/filters/account_centric_monitoring.lua`
   - Tracks IPs attempting to access specific accounts
   - Detects when many unique IPs target a single account
2. ✅ Enhance the neural network with new features
   - Implemented in `server/lua-plugins.d/features/neural_enhanced.lua`
   - Adds global and account-specific features to the neural network
   - Features include global auth rate, IP-user ratio, and account targeting score
3. ✅ Develop anomaly detection algorithms for global patterns
   - Implemented as part of the dynamic response mechanism
   - Detects sudden spikes in authentication attempts and unique IPs

### Phase 3: Response Mechanisms

1. ✅ Implement dynamic response mechanisms
   - Implemented in `server/lua-plugins.d/actions/dynamic_response.lua`
   - Applies different countermeasures based on threat level
   - Measures include captcha, rate limiting, and geographic filtering
2. ✅ Create administrative interfaces for manual intervention
   - Implemented in `server/lua-plugins.d/hooks/distributed-brute-force-admin.lua`
   - Provides endpoints for viewing metrics and resetting protection measures
   - Allows administrators to monitor and manage the protection system
3. ✅ Develop automated testing tools to validate effectiveness
   - Implemented in `server/lua-plugins.d/hooks/distributed-brute-force-test.lua`
   - Provides tools to simulate distributed attacks and verify detection
   - Includes comprehensive testing functionality with detailed reporting

### Phase 4: Continuous Improvement

1. ✅ Implement feedback loops for detection accuracy
   - The neural network can be retrained with new data
   - Implemented feedback mechanism in `server/lualib/feedback.go`
   - Created Lua hook for feedback in `server/lua-plugins.d/hooks/neural-feedback.lua`
   - Added automatic retraining when sufficient feedback samples are collected
   - Feedback is prioritized in training to improve detection accuracy
2. ✅ Develop adaptive thresholds based on historical data
   - Threat levels are calculated based on historical patterns
   - Sudden changes from baseline trigger higher threat levels
3. ⏳ Create reporting tools for security analysis
   - Metrics and threat levels are logged for analysis

## Implementation Status

The distributed brute force detection and mitigation system has been implemented with the following components:

1. **Global Pattern Monitoring** (`server/lua-plugins.d/features/global_pattern_monitoring.lua`)
   - Tracks authentication attempts, unique IPs, and unique usernames in sliding windows
   - Calculates and stores metrics like attempts per IP, attempts per user, and IPs per user
   - Maintains historical data for anomaly detection
   - Uses atomic Redis operations to prevent race conditions

2. **Account-Centric Monitoring** (`server/lua-plugins.d/filters/account_centric_monitoring.lua`)
   - Tracks IPs attempting to access specific accounts
   - Detects when many unique IPs target a single account
   - Identifies accounts under distributed brute force attack
   - Uses atomic Redis operations to prevent race conditions

3. **Enhanced Neural Network** (`server/lua-plugins.d/features/neural_enhanced.lua`)
   - Adds global and account-specific features to the neural network
   - Improves detection of distributed attacks with new metrics
   - Integrates with existing neural network infrastructure

4. **Dynamic Response Mechanisms** (`server/lua-plugins.d/actions/dynamic_response.lua`)
   - Calculates threat levels based on multiple factors
   - Applies different countermeasures based on threat severity
   - Implements progressive security measures like captcha, rate limiting, and geographic filtering
   - Uses atomic Redis operations to prevent race conditions
   - Sends email notifications to administrators about detected threats

5. **Redis Lua Scripts for Atomic Operations** (`server/lua-plugins.d/init/init_neural.lua`)
   - Implements Redis Lua scripts for atomic operations to prevent race conditions
   - Ensures data consistency in high-concurrency scenarios
   - Provides better performance by reducing the number of Redis round-trips
   - Automatically uploads scripts during initialization

### Race Condition Prevention

To ensure data consistency in high-concurrency scenarios, we've implemented Redis Lua scripts for atomic operations. These scripts combine multiple Redis commands into a single atomic operation, preventing race conditions that could occur when multiple instances of Nauthilus are running concurrently.

The following Redis Lua scripts have been implemented:

1. **ZAddRemExpire**: Combines ZADD, ZREMRANGEBYSCORE, and EXPIRE operations
   - Used for tracking authentication attempts, unique IPs, and unique usernames in sliding windows
   - Ensures that data is consistently added, pruned, and given an expiration time

2. **HSetMultiExpire**: Combines multiple HSET operations and an EXPIRE operation
   - Used for storing metrics and settings with a single atomic operation
   - Ensures that all fields are updated together and given an expiration time

3. **SAddMultiExpire**: Combines multiple SADD operations and an EXPIRE operation
   - Used for adding multiple members to a set and setting an expiration time
   - Ensures that all members are added together and the set is given an expiration time

4. **ExistsHSetMultiExpire**: Checks if a key exists, and if not, performs multiple HSET operations and an EXPIRE operation
   - Used for storing historical metrics only if they don't already exist
   - Ensures that historical data is not overwritten by concurrent operations

These scripts are automatically uploaded to Redis during initialization by the `init_neural.lua` script.

### Pending Tasks

The following tasks are still pending:

1. **Visualization Tools**
   - Develop tools to visualize the metrics collected by the system
   - Create dashboards for monitoring global authentication patterns

2. **Administrative Interfaces**
   - Create interfaces for manual intervention during attacks
   - Develop tools for managing response mechanisms

3. **Testing and Validation**
   - Develop automated testing tools to validate effectiveness
   - Create simulated attack scenarios for testing

4. **Feedback Loops and Reporting**
   - Implement feedback loops for improving detection accuracy
   - Create comprehensive reporting tools for security analysis

## Integration Guide

This section provides instructions for integrating the distributed brute force detection and mitigation system into your Nauthilus deployment.

### Configuration in nauthilus.yml

To enable the distributed brute force detection and mitigation system, you need to add the following configuration to your `nauthilus.yml` file:

```yaml
lua:
  # Add the features for global pattern monitoring and neural network enhancement
  features:
    - name: "global_pattern_monitoring"
      script_path: "/etc/nauthilus/lua-plugins.d/features/global_pattern_monitoring.lua"
    - name: "neural_enhanced"
      script_path: "/etc/nauthilus/lua-plugins.d/features/neural_enhanced.lua"

  # Add the filter for account-centric monitoring
  filters:
    - name: "account_centric_monitoring"
      script_path: "/etc/nauthilus/lua-plugins.d/filters/account_centric_monitoring.lua"

  # Add the action for dynamic response
  actions:
    - type: "post"
      name: "dynamic_response"
      script_path: "/etc/nauthilus/lua-plugins.d/actions/dynamic_response.lua"

  # Configure the initialization script
  config:
    # If you're using a single init script
    init_script_path: "/etc/nauthilus/lua-plugins.d/init/init.lua"

    # If you're using multiple init scripts (v1.7.7+)
    init_script_paths:
      - "/etc/nauthilus/lua-plugins.d/init/init.lua"
      - "/etc/nauthilus/lua-plugins.d/init/init_neural.lua"
```

### Required Environment Variables

The dynamic response mechanism uses email notifications to alert administrators about detected threats. The following environment variables are required for email notifications:

```bash
# SMTP Configuration
SMTP_USE_LMTP=false
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_HELO_NAME=nauthilus.example.com
SMTP_TLS=false
SMTP_STARTTLS=true
SMTP_USERNAME=notifications@example.com
SMTP_PASSWORD=your-smtp-password
SMTP_MAIL_FROM=notifications@example.com

# Administrator Email Addresses (comma-separated list)
ADMIN_EMAIL_ADDRESSES=admin1@example.com,admin2@example.com
```

### Redis Configuration

The distributed brute force detection system relies heavily on Redis for storing metrics and state information. Ensure that your Redis configuration is properly set up in the `nauthilus.yml` file:

```yaml
server:
  redis:
    # Redis connection settings
    database_number: 0
    prefix: "nauthilus:"
    pool_size: 10
    idle_pool_size: 2
    positive_cache_ttl: 3600s
    negative_cache_ttl: 3600s

    # Redis server configuration
    master:
      address: "127.0.0.1:6379"
      username: ""
      password: ""
```

### Neural Network Configuration

To optimize the neural network for distributed brute force detection, configure the neural network settings in the `nauthilus.yml` file:

```yaml
brute_force:
  neural_network:
    max_training_records: 20000
    hidden_neurons: 12
    activation_function: "tanh"
    static_weight: 0.5
    ml_weight: 0.5
    threshold: 0.7
    learning_rate: 0.005
```

### Deployment Steps

1. **Copy Lua Scripts**: Copy all the Lua scripts to your Nauthilus server:
   ```bash
   cp -r server/lua-plugins.d/features/global_pattern_monitoring.lua /etc/nauthilus/lua-plugins.d/features/
   cp -r server/lua-plugins.d/features/neural_enhanced.lua /etc/nauthilus/lua-plugins.d/features/
   cp -r server/lua-plugins.d/filters/account_centric_monitoring.lua /etc/nauthilus/lua-plugins.d/filters/
   cp -r server/lua-plugins.d/actions/dynamic_response.lua /etc/nauthilus/lua-plugins.d/actions/
   cp -r server/lua-plugins.d/init/init_neural.lua /etc/nauthilus/lua-plugins.d/init/
   ```

2. **Update Configuration**: Update your `nauthilus.yml` file with the configuration shown above.

3. **Set Environment Variables**: Set the required environment variables for email notifications.

4. **Restart Nauthilus**: Restart the Nauthilus service to apply the changes:
   ```bash
   systemctl restart nauthilus
   ```

5. **Verify Installation**: Check the Nauthilus logs to verify that the scripts are loaded and running correctly:
   ```bash
   journalctl -u nauthilus -f
   ```

### Monitoring and Tuning

After deployment, monitor the system's performance and adjust the configuration as needed:

1. **Threshold Tuning**: Adjust the thresholds in the account_centric_monitoring.lua script (threshold_unique_ips and threshold_ip_to_fail_ratio) based on your environment.

2. **Neural Network Tuning**: Adjust the neural network parameters in the nauthilus.yml file to optimize detection accuracy.

3. **Redis Performance**: Monitor Redis performance and adjust connection pool settings if needed.

4. **Log Analysis**: Regularly review the Nauthilus logs to identify potential issues or areas for improvement.

## Conclusion

Distributed brute force attacks represent a sophisticated threat that requires a multi-layered defense strategy. By combining global pattern recognition, account-centric monitoring, real-time anomaly detection, and dynamic response mechanisms, Nauthilus can effectively detect and mitigate these attacks.

The implemented approach leverages Nauthilus's existing strengths—Lua extensibility, Redis integration, and neural network capabilities—while adding new dimensions of analysis that focus on system-wide patterns and account-specific behaviors.

With these enhancements, Nauthilus is now able to detect and respond to distributed brute force attacks that would otherwise bypass traditional IP-based protection mechanisms. The system provides a comprehensive defense against sophisticated attackers using large pools of IP addresses to conduct brute force attacks.
