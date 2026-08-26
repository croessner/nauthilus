# Distributed Brute Force Attack Detection and Mitigation

## Overview

This document outlines a comprehensive approach to detecting and mitigating distributed brute force attacks that bypass traditional IP-based brute force protection mechanisms. It addresses scenarios where attackers use a large number of unique IP addresses (potentially millions) with a small number of login attempts per IP to avoid triggering traditional brute force detection systems.

> **Production status:** This is an architecture and threat-analysis document, not a current deployment runbook. The
> Lua snippets and the bundled global-pattern, account-monitoring, and dynamic-response callbacks below require mutable
> Redis, ambient configuration, mail, or other host capabilities that the generation-owned authentication Policy VM
> deliberately does not expose. Do not place those scripts in top-level `policy`; candidate preparation rejects them.
> See [`../lua-plugins.d/POLICY_VM_COMPATIBILITY.md`](../lua-plugins.d/POLICY_VM_COMPATIBILITY.md) for the normative
> checked-in callback classification.

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

While these mechanisms are effective against traditional brute force attacks, they have limitations when facing distributed attacks:

- **IP-based Protection**: Ineffective when each IP makes only 1-2 attempts
- **Adaptive Toleration**: Still primarily focused on individual IP behavior

## Enhanced Detection Strategy

To effectively detect and mitigate distributed brute force attacks, we propose a multi-layered approach that combines:

1. **Global Pattern Recognition**: Detecting abnormal authentication patterns across the entire system
2. **Account-Centric Monitoring**: Focusing on unusual activity targeting specific accounts
3. **Dynamic Response Mechanisms**: Implementing adaptive countermeasures based on threat severity

### 1. Global Pattern Recognition

#### Implementation with Lua and Redis

```lua
-- Example Lua script for global pattern monitoring
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

### 3. Real-time Anomaly Detection

Note: As of v1.8.0, the previous neural network component has been removed. Detection now relies on metrics- and rules-based approaches described in sections 1 and 2, combined with dynamic response mechanisms in section 4.

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
        -- increase_ml_sensitivity() -- removed (ML dropped in v1.8.0)
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

### Historical Lua prototype mapping

The reference collection maps global recognition to `environment/global_pattern_monitoring.lua`, account evidence to
`subject/account_centric_monitoring.lua`, and response experiments to `actions/dynamic_response.lua`. The custom admin
and simulation hooks remain separate process-owned HTTP callbacks. This mapping documents the prototype; it is not a
Policy activation surface.

The prototype stores sliding-window counters, distributed state, and historical patterns in Redis. It also contains
atomic Redis scripts used to combine related mutations:

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

The process-owned historical initialization script can upload those Redis programs when explicitly configured. That
process lifecycle does not make any reference-only authentication callback selectable by top-level `policy`.

### Future design work

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

## Security Considerations

### Metrics Endpoint Authentication

The metrics endpoint (`/metrics`) can be protected with dedicated HTTP Basic authentication to prevent unauthorized access to sensitive monitoring data.
This protection is independent of `auth.backchannel.basic_auth` and `auth.backchannel.oidc_bearer`.

The following modes are supported:

1. **Dedicated Basic Authentication**: If `observability.metrics.endpoint_auth.basic.enabled=true`, clients must provide the configured metrics credentials.
2. **No Authentication**: If metrics endpoint Basic authentication is disabled or omitted, `/metrics` is accessible without authentication.

Bearer or OIDC authentication is not accepted for `/metrics`.

```yaml
observability:
  metrics:
    endpoint_auth:
      basic:
        enabled: true
        username: prometheus
        password: your-dedicated-metrics-password
```

#### Configuring Prometheus to Access Secured Metrics

To configure Prometheus to access the secured metrics endpoint, you need to add authentication configuration to your Prometheus scrape configuration:

##### Basic Authentication

```yaml
scrape_configs:
  - job_name: 'nauthilus'
    metrics_path: '/metrics'
    basic_auth:
      username: 'your_username'
      password: 'your_password'
    static_configs:
      - targets: ['nauthilus:8080']
```

## Production integration boundary

The built-in `authn/builtin/brute_force` provider remains available through an explicit top-level authn domain plan.
The broader distributed detector described here is not a completed production feature under the hard-cut Policy
runtime:

- `environment/global_pattern_monitoring.lua` requires Redis scripts and writes;
- `subject/account_centric_monitoring.lua` requires Redis scripts, writes, and ambient tuning values;
- `actions/dynamic_response.lua` requires Redis writes/scripts, mail, and ambient SMTP/tuning values.

Those capabilities are intentionally absent from the request-owned Policy VM, so there is no supported YAML block,
environment-variable recipe, copy step, or reload procedure for activating these three callbacks. A production
implementation must first provide generation-owned native or builtin providers/effects with typed configuration,
bounded targets, candidate validation, and explicit policy selection. Until such components exist and pass the normal
prepare/validate/commit gate, this document supplies threat-model and algorithm material only.

## Conclusion

Distributed brute force attacks require global and account-centric evidence in addition to per-source throttling. The
algorithms above remain useful design input, but their historical Lua implementations are not production authority and
must not be presented as deployed protection.
