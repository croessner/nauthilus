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
