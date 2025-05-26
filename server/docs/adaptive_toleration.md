# Adaptive Toleration Mechanism

## Overview

The adaptive toleration mechanism is an advanced feature in Nauthilus that dynamically adjusts the tolerance threshold for failed authentication attempts based on the volume of successful authentications. Unlike static toleration, which uses a fixed percentage, adaptive toleration scales the tolerance threshold according to the authentication patterns observed from a specific IP address.

## How It Works

### Concept

The core concept behind adaptive toleration is that the acceptable ratio of failed to successful authentication attempts should scale with the volume of legitimate traffic. For example:

- An IP address with few successful authentications might be allowed only a small number of failures
- An IP address with many successful authentications (like a corporate proxy) might be allowed a higher number of failures

### Algorithm

The adaptive toleration algorithm uses the following parameters:

1. **Minimum Toleration Percentage**: The lowest toleration percentage allowed, regardless of traffic volume
2. **Maximum Toleration Percentage**: The highest toleration percentage allowed, even for very high traffic volumes
3. **Scale Factor**: Controls how quickly the toleration percentage increases with traffic volume

The algorithm calculates the toleration percentage using a logarithmic scale:

```
factor = min(1, log(positive_count + 1) / log(100) * scale_factor)
percent = min_percent + (max_percent - min_percent) * factor
```

Where:
- `positive_count` is the number of successful authentications
- `factor` is a value between 0 and 1 that represents how far to scale between min and max
- The resulting `percent` is used to calculate the maximum allowed negative attempts

### Implementation

The implementation uses a Redis Lua script to perform the calculation atomically. The script:

1. Retrieves the counts of positive (successful) and negative (failed) authentication attempts
2. Calculates the appropriate toleration percentage based on the algorithm
3. Determines the maximum allowed negative attempts
4. Returns the results along with a flag indicating whether adaptive toleration was used

## Configuration

### Global Configuration

Adaptive toleration can be enabled globally in the configuration file:

```yaml
brute_force:
  adaptive_toleration: true
  min_tolerate_percent: 10  # Default: 10%
  max_tolerate_percent: 50  # Default: 50%
  scale_factor: 1.0         # Default: 1.0
```

### Per-IP Configuration

You can also configure adaptive toleration for specific IP addresses or networks:

```yaml
brute_force:
  custom_tolerations:
    - ip_address: "192.168.1.0/24"
      tolerate_percent: 20
      tolerate_ttl: 24h
      adaptive_toleration: true
      min_tolerate_percent: 15
      max_tolerate_percent: 60
      scale_factor: 1.5
```

### Parameters

- **adaptive_toleration**: Boolean flag to enable/disable adaptive toleration
- **min_tolerate_percent**: The minimum toleration percentage (0-100)
- **max_tolerate_percent**: The maximum toleration percentage (0-100)
- **scale_factor**: Controls how quickly the percentage scales (0.1-10.0)
  - Values < 1.0: Slower scaling (more conservative)
  - Values > 1.0: Faster scaling (more permissive)

## Benefits Over Static Toleration

1. **Automatic Adjustment**: The system automatically adjusts to different traffic patterns without manual intervention
2. **Better Protection for Low-Volume Sources**: Applies stricter limits to IP addresses with few legitimate authentications
3. **Reduced False Positives**: Allows more failures for high-volume legitimate sources like corporate proxies
4. **Balanced Security**: Maintains security while reducing the need for whitelisting

## Example Scenarios

### Low-Volume Client

A single user connecting from home:
- 5 successful logins
- Using default settings (min=10%, max=50%, scale=1.0)
- Calculated toleration: ~12%
- Maximum allowed failures: 0 (since 12% of 5 is less than 1)

### Medium-Volume Proxy

A small office proxy:
- 50 successful logins
- Using default settings
- Calculated toleration: ~30%
- Maximum allowed failures: 15

### High-Volume Proxy

A large corporate proxy:
- 500 successful logins
- Using default settings
- Calculated toleration: ~45%
- Maximum allowed failures: 225

## Fallback Behavior

If the Redis Lua script execution fails for any reason, the system automatically falls back to using the static toleration percentage defined in the configuration.

## Handling Persistent Wrong Passwords

### Individual Users with Incorrect Passwords

When a user consistently enters an incorrect password (perhaps due to not noticing a caps lock is on or forgetting a recent password change):

- If the user has no successful logins from their IP address, they will not be tolerated at all, as the system requires at least one successful authentication to establish a baseline
- Once the user has successfully authenticated at least once, the system will allow a small number of failed attempts based on the calculated toleration percentage
- The toleration percentage starts at the minimum value (default 10%) for users with few successful logins

### Corporate Environments with Multiple Users

The adaptive toleration mechanism is particularly beneficial for corporate environments where multiple users share the same IP address (e.g., through a proxy):

- The system counts successful authentications from all users behind the IP address
- As more users successfully authenticate, the toleration percentage increases (up to the configured maximum)
- This automatically accommodates situations where a few users might have incorrect passwords among many legitimate users
- Example: In a company with 100 successful logins, using default settings (min=10%, max=50%, scale=1.0):
  - Calculated toleration: ~40%
  - Maximum allowed failures: 40
  - This allows for several users to have password issues without triggering brute force protection

This approach provides a balance between security and usability, particularly for shared IP scenarios, without requiring manual configuration adjustments.
