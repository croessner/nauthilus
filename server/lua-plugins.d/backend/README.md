# Backend Plugins for Nauthilus

This directory contains Lua backend plugins for the Nauthilus authentication system. Backend plugins provide integration with external data sources for user authentication, account management, and credential verification.

## Available Plugins

### backend.lua
Implements a MySQL backend for user authentication and account management, demonstrating how to integrate Nauthilus with a relational database.

**Features:**
- Verifies user passwords against credentials stored in a MySQL database
- Lists accounts from the database for administrative purposes
- Manages TOTP (Time-based One-Time Password) secrets for two-factor authentication
- Supports attribute filtering based on the authentication protocol
- Handles unique user IDs and display names
- Provides a reference implementation for custom backend integrations

**Usage:**
The plugin connects to a MySQL database using the configuration specified in the plugin code. To use this plugin:

1. Create the required MySQL table structure:
```sql
CREATE TABLE `nauthilus` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `account` varchar(255) NOT NULL,
  `totp_secret` varchar(255) DEFAULT NULL,
  `uniqueid` varchar(255) NOT NULL,
  `display_name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UsernameIdx` (`username`),
  UNIQUE KEY `AccountIdx` (`account`),
  UNIQUE KEY `UniqueidIdx` (`uniqueid`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
```

2. Modify the database connection string in the plugin to match your MySQL server configuration:
```lua
local mysql, err_open = db.open("mysql", "nauthilus:nauthilus@tcp(127.0.0.1)/nauthilus", config)
```

3. Configure the plugin in your Nauthilus configuration to use it as the authentication backend.

**Customization:**
This plugin can be used as a template for creating custom backend integrations. To create your own backend:

1. Copy this file and modify the database connection and queries to match your database schema
2. Implement the required functions:
   - `nauthilus_backend_verify_password`: Verifies user credentials
   - `nauthilus_backend_list_accounts`: Lists available accounts
   - `nauthilus_backend_add_totp`: Adds TOTP secrets for 2FA

**Security Considerations:**
- The example code uses string concatenation for SQL queries, which is vulnerable to SQL injection. In a production environment, you should use prepared statements or parameterized queries.
- Passwords should be stored using strong hashing algorithms (the example assumes this is already handled).
- Database connection credentials should be stored securely and not hardcoded in the plugin.

### proxy_backend.lua

Implements a full Lua proxy backend that forwards all backend operations to an upstream Nauthilus instance via HTTP,
including WebAuthn CRUD calls.

**Features:**

- Proxies `verify_password` and `list_accounts` to `/api/v1/auth/json` (mode `list-accounts`)
- Proxies TOTP secret and recovery code operations to the backchannel MFA API
- Proxies WebAuthn credential CRUD to the backchannel MFA API
- Adds OpenTelemetry spans and Prometheus metrics for upstream HTTP calls
- Supports auth to upstream via bearer token or HTTP Basic auth

**Usage:**

1. Enable the proxy backend in your Nauthilus config and point it to this script.
2. Configure the upstream URL and credentials via environment variables or `nauthilus_proxy_backend` table (see below).
3. Ensure the upstream instance exposes the required backchannel endpoints and is protected by Basic auth or JWT.

**Configuration (environment variables):**

- `PROXY_BACKEND_UPSTREAM_URL` (default: `http://127.0.0.1:9080`)
- `PROXY_BACKEND_AUTH_PATH` (default: `/api/v1/auth/json`)
- `PROXY_BACKEND_MFA_PATH` (default: `/api/v1/mfa-backchannel`)
- `PROXY_BACKEND_TIMEOUT` (default: `5s`)
- `PROXY_BACKEND_LIST_ACCOUNTS_USERNAME` (default: `list-accounts`)
- `PROXY_BACKEND_TYPE` (default: `lua`)
- `PROXY_BACKEND_NAME` (default: `default`)
- `PROXY_BACKEND_AUTH_TOKEN` (default: empty)
- `PROXY_BACKEND_BASIC_USER` (default: empty)
- `PROXY_BACKEND_BASIC_PASS` (default: empty)

**Configuration (Lua table override):**
If you set a global table named `nauthilus_proxy_backend`, its fields override the environment defaults:

```lua
nauthilus_proxy_backend = {
  base_url = "http://upstream:9080",
  auth_path = "/api/v1/auth/json",
  mfa_path = "/api/v1/mfa-backchannel",
  timeout = "5s",
  list_accounts_username = "list-accounts",
  backend = "lua",
  backend_name = "default",
  auth_token = "",
  basic_user = "",
  basic_pass = "",
}
```

**Upstream API expectations:**

- `POST {base_url}{auth_path}` with JSON credentials for authentication
- `GET {base_url}{auth_path}?mode=list-accounts` for account listing
- Backchannel MFA endpoints must be available for TOTP, recovery codes, and WebAuthn operations

**Security Considerations:**

- Use TLS for upstream connections in production.
- Protect backchannel endpoints with Basic auth or JWT.
- Avoid sending secrets to untrusted upstreams.
