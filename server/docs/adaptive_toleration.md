# Adaptive Toleration Mechanism

## Overview

The adaptive toleration mechanism is an advanced feature in Nauthilus that dynamically adjusts the tolerance threshold for failed authentication attempts based on the volume of successful authentications. Unlike static toleration, which uses a fixed percentage, adaptive toleration scales the tolerance threshold according to the authentication patterns observed from a specific IP address.

## How It Works

### Concept

The core concept behind adaptive toleration is that the acceptable ratio of failed to successful authentication attempts should scale with the volume of legitimate traffic. For example:

- An IP address with few successful authentications might be allowed only a small number of failures
- An IP address with many successful authentications (like a corporate proxy) might be allowed a higher number of failures

### Counting Semantics

Toleration counters are kept per client address (scoped by `ip_scoping` for tolerations) and cover only the
`tolerate_ttl` window:

- **positive** is the number of *distinct accounts* that authenticated successfully from the address within the
  window. Repeated logins of the same account count once, so one valid account cannot buy failed attempts by logging
  in repeatedly.
- **negative** is the number of *failed login attempts* from the address within the window, independent of the
  attacked account. Ten failures against one account count ten times.
- A failure that repeats an already recorded wrong password of the same account (repeating wrong password, RWP) is
  not counted, exactly like the brute-force buckets. A client retrying one stale password therefore cannot exhaust
  the toleration of a shared address, while every new password guess counts.
- Only host-verified credential outcomes are counted. Temporary failures, pre-authentication rejections (for example
  an existing ban), identity lookups, and no-auth requests are not counted.
- Both counters are counted on read over exactly the window (`ZCOUNT` on the `bf:tr:{<scoped ip>}:P` and `:N` sorted
  sets), so every instance sees the same values and successes age out even while an address goes quiet. Each new
  event purges expired members, and idle sets expire with their key. At most 10,000 failed attempts are retained per
  address; a saturated count is never tolerated.

An address is tolerated while `negative <= floor(percent * positive / 100)` and `positive > 0`. A tolerated address
does not get banned when a bucket exceeds its limit. As soon as the failed attempts exceed the allowance, toleration
ends and the bucket limits apply again, so an attack from a shared address is stopped once it outgrows the share of
failures the legitimate accounts behind it justify. `max_tolerate_percent` is the upper bound of that share.

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
- `positive_count` is the number of distinct accounts with a successful authentication within the window
- `factor` is a value between 0 and 1 that represents how far to scale between min and max
- The resulting `percent` is used to calculate the maximum allowed negative attempts

### Implementation

Each decision:

1. Counts positive (distinct successful accounts) and negative (failed attempts) events within the window with one
   read-only `ZCOUNT` pipeline, which a Redis Cluster may serve from replicas
2. Calculates the toleration percentage with the algorithm above
3. Determines the maximum allowed negative attempts

Events are written by the `RecordTolerationEvent` script, which adds the event, purges expired members and caps the
negative set atomically. The bucket limits use the same percentage formula in the `SlidingWindowCounter` script.

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

All examples use the default settings (min=10%, max=50%, scale=1.0) and count events within `tolerate_ttl`.

### Low-Volume Client

A single user connecting from home:
- 1 account with any number of successful logins
- Calculated toleration: 16%
- Maximum allowed failures: 0 (since 16% of 1 is less than 1)

### Small Office

- 5 accounts with successful logins
- Calculated toleration: 25%
- Maximum allowed failures: 1

### Medium-Volume Proxy

- 50 accounts with successful logins
- Calculated toleration: 44%
- Maximum allowed failures: 22

### High-Volume Proxy

- 500 accounts with successful logins
- Calculated toleration: 50% (capped by `max_tolerate_percent`)
- Maximum allowed failures: 250

### Attack From Behind Valid Accounts

An attacker controls 10 valid accounts and attacks an eleventh account from the same address:
- 10 accounts with successful logins, calculated toleration: 30%
- Maximum allowed failures: 3
- The fourth failed attempt within the window ends toleration; from then on the regular bucket limits apply and the
  address is banned once a bucket is exceeded. Logging in again with the same 10 accounts does not raise the
  allowance, and the successes age out of the window after `tolerate_ttl` even while the attack continues.

## Fallback Behavior

If the counters cannot be read, the address is not tolerated for that request and the regular bucket limits apply.

## Handling Persistent Wrong Passwords

### Individual Users with Incorrect Passwords

When a user consistently enters an incorrect password (perhaps due to not noticing a caps lock is on or forgetting a recent password change):

- If the user has no successful logins from their IP address, they will not be tolerated at all, as the system requires at least one successful authentication to establish a baseline
- Once the user has successfully authenticated at least once, the system will allow a small number of failed attempts based on the calculated toleration percentage
- Retrying the same wrong password is a repeating wrong password and does not count as a new failed attempt
- The toleration percentage starts at the minimum value (default 10%) for users with few successful logins

### Corporate Environments with Multiple Users

The adaptive toleration mechanism is particularly beneficial for corporate environments where multiple users share the same IP address (e.g., through a proxy):

- The system counts the distinct accounts that authenticated successfully behind the IP address
- As more users successfully authenticate, the toleration percentage increases (up to the configured maximum)
- This automatically accommodates situations where a few users might have incorrect passwords among many legitimate users
- Example: In a company with 100 accounts that logged in successfully, using default settings (min=10%, max=50%, scale=1.0):
  - Calculated toleration: 50%
  - Maximum allowed failures within the window: 50
  - This allows for several users to have password issues without triggering brute force protection

This approach provides a balance between security and usability, particularly for shared IP scenarios, without requiring manual configuration adjustments.
