# Action Plugins for Nauthilus

This directory contains Lua action plugins for the Nauthilus authentication system. Action plugins are executed in response to authentication events and can perform various tasks such as tracking failed logins, implementing dynamic security responses, and sending notifications.

## Available Plugins

### analytics.lua
A plugin that collects and analyzes authentication data for reporting and visualization purposes. It tracks successful and failed login attempts, user behavior patterns, and system usage statistics.

**Features:**
- Tracks authentication metrics by user, IP, and time
- Stores data in Redis for later analysis
- Supports data aggregation for reporting dashboards
- Provides insights into system usage patterns

**Usage:**
The plugin runs automatically on each authentication attempt. No manual configuration is required beyond enabling the plugin in your Nauthilus configuration.

### bruteforce.lua
Detects and mitigates brute force attacks by monitoring failed login attempts and implementing countermeasures when suspicious activity is detected.

**Features:**
- Tracks failed login attempts by IP address and username
- Implements progressive delays for repeated failed attempts
- Can temporarily block IPs with excessive failed attempts
- Logs detailed information about potential brute force attacks

**Usage:**
Configure the plugin through environment variables:
- `HAPROXY_STATS`: HAProxy stats socket endpoint
- `HAPROXY_SMTP_MAP`: HAProxy map file for SMTP protocol
- `HAPROXY_GENERIC_MAP`: HAProxy map file for other protocols

### dynamic_response.lua
Implements a sophisticated security response system that dynamically adjusts security measures based on detected threat levels.

**Features:**
- Calculates threat levels based on login patterns, geographic distribution, and other metrics
- Implements different security measures based on the threat level (severe, high, moderate, normal)
- Notifies administrators via email about security threats
- Uses Redis to store and track metrics, suspicious IPs, and regions
- Dynamically adjusts security settings like captcha requirements and rate limiting

**Usage:**
Configure the plugin through environment variables:
- `SMTP_*` variables for email notifications
- `ADMIN_EMAIL_ADDRESSES`: Comma-separated list of admin email addresses for notifications
- `CUSTOM_REDIS_POOL_NAME`: Optional custom Redis pool name

The plugin automatically calculates threat levels and applies appropriate security measures without manual intervention.

### failed_login_tracker.lua
Tracks failed login attempts for unrecognized accounts, maintaining a top-100 list of usernames with the most failed attempts.

**Features:**
- Tracks failed login attempts in a Redis sorted set
- Only tracks logins for unrecognized accounts (to avoid penalizing legitimate users who mistype passwords)
- Maintains a top-100 list of failed logins
- Provides logging and context information

**Usage:**
The plugin runs automatically on each authentication attempt. You can optionally configure a custom Redis pool using the `CUSTOM_REDIS_POOL_NAME` environment variable.

### haveibeenpwnd.lua
Checks user credentials against the "Have I Been Pwned" database to identify compromised passwords.

**Features:**
- Securely checks passwords against known data breaches
- Uses k-anonymity to protect user privacy during checks
- Alerts users and administrators about compromised credentials
- Integrates with the Nauthilus notification system

**Usage:**
Configure the plugin through environment variables:
- `CUSTOM_REDIS_POOL_NAME`: Optional custom Redis pool name
- `SMTP_*` variables: SMTP server configuration for sending notifications (SMTP_USE_LMTP, SMTP_SERVER, SMTP_PORT, SMTP_HELO_NAME, SMTP_TLS, SMTP_STARTTLS, SMTP_USERNAME, SMTP_PASSWORD, SMTP_MAIL_FROM)
- `SSP_WEBSITE`: URL to the self-service password change website

### telegram.lua
Sends security notifications and alerts to a Telegram channel or group.

**Features:**
- Sends real-time security alerts to Telegram
- Configurable notification levels (critical, warning, info)
- Supports rich text formatting for better readability
- Can include detailed metrics and threat information

**Usage:**
Configure the plugin through environment variables:
- `TELEGRAM_PASSWORD`: Your Telegram bot token/password
- `TELEGRAM_CHAT_ID`: The chat ID to send notifications to
