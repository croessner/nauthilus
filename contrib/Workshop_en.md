# Nauthilus Workshop

## Introduction to Nauthilus

Nauthilus is a universal authentication and authorization platform written in Go. It serves as a central point for various authentication requests, for example from mail servers or websites. Nauthilus offers a flexible and extensible architecture that allows the use of different backends for authentication and customization of behavior through Lua scripts.

### Main Features

- **Universal Authentication**: Supports various protocols and services
- **Flexible Backend Integration**: LDAP, databases, and custom Lua backends
- **Extensibility through Lua**: Features and filters can be implemented in Lua
- **Monitoring and Metrics**: Integration with Prometheus and Grafana
- **Brute Force Detection**: Protection against brute force attacks
- **Geolocation**: Filtering based on geographic location
- **High Availability**: Support for clustering and load balancing

### Architecture of Nauthilus

Nauthilus consists of several components that work together to form a flexible and extensible authentication platform:

1. **HTTP Server**: Receives authentication requests via HTTP/HTTPS
2. **Backend Systems**: Connect to various authentication sources (LDAP, databases, etc.)
3. **Lua Script Engine**: Enables extension and customization of behavior
   - **Features**: Extend functionality during request processing
   - **Filters**: Validate requests after backend processing
   - **Post-Actions**: Perform asynchronous actions after completion of main processing
   - **Custom Hooks**: Enable custom HTTP endpoints with their own logic
4. **Redis Cache**: Stores session information and intermediate results
5. **Monitoring System**: Collects metrics and enables monitoring

The architecture follows a modular approach where different components can be developed and configured independently:

```
+----------------+     +----------------+     +----------------+
|                |     |                |     |                |
| Mail Server    |     | Web Server     |     | Other Services |
| (Postfix,      |     | (Nginx,        |     |                |
|  Dovecot)      |     |  Apache)       |     |                |
|                |     |                |     |                |
+-------+--------+     +-------+--------+     +-------+--------+
        |                      |                      |
        v                      v                      v
+---------------------------------------------------------------+
|                                                               |
|                      HTTP/HTTPS API                           |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                         Nauthilus                             |
|                                                               |
|  +---------------+    +---------------+    +---------------+  |
|  |               |    |               |    |               |  |
|  | Lua Features  |    | Lua Filter    |    | Lua Backends  |  |
|  |               |    |               |    |               |  |
|  +---------------+    +---------------+    +---------------+  |
|                                                               |
|  +---------------+    +---------------+                       |
|  |               |    |               |                       |
|  | Post-Actions  |    | Custom Hooks  |                       |
|  |               |    |               |                       |
|  +---------------+    +---------------+                       |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                       Redis Cache                             |
|                                                               |
+---------------------------------------------------------------+
        |                      |                      |
        v                      v                      v
+----------------+     +----------------+     +----------------+
|                |     |                |     |                |
| LDAP Server    |     | Database       |     | External APIs  |
|                |     |                |     |                |
+----------------+     +----------------+     +----------------+
```

### Request Processing

When an authentication request arrives at Nauthilus, it goes through several processing steps:

1. **Request Reception**: The request is received via HTTP/HTTPS
2. **Feature Processing**: Lua features are executed to provide additional functionality
3. **Backend Processing**: The request is forwarded to the configured backend
4. **Filter Processing**: Lua filters are applied to validate the request
5. **Response Generation**: A response is generated and sent back
6. **Post-Actions**: After completion of the main processing, asynchronous actions are executed

Post-Actions are executed asynchronously after the response has already been sent to the client. They can be used for various purposes, such as:

- Logging of authentication attempts
- Notifications about successful or failed login attempts
- Updating statistics or metrics
- Integration with external systems

In addition to regular request processing, Nauthilus also offers **Custom Hooks**, which allow the creation of custom HTTP endpoints with their own logic. These hooks are called via special URLs and can be used for various purposes, such as:

- Providing custom APIs
- Integration with other systems
- Implementation of special functions that are not part of the standard authentication process

This processing chain allows flexible adaptation of the authentication process to specific requirements.

## Installation and Setup

### Prerequisites

- Go 1.24.x or higher
- Redis (for caching and session management)
- Optional: MySQL/MariaDB (for database backend)
- Optional: LDAP server (for LDAP backend)

### Installation

#### Via Docker

The easiest way to install Nauthilus is via Docker:

```bash
docker pull ghcr.io/croessner/nauthilus:latest
```

Start the container with:

```bash
docker run -d --name nauthilus \
  -p 8080:8080 \
  -v /path/to/config:/etc/nauthilus \
  ghcr.io/croessner/nauthilus:latest
```

#### Docker Compose

For a more complex environment with Redis, you can use Docker Compose:

```yaml
version: '3'

services:
  nauthilus:
    image: ghcr.io/croessner/nauthilus:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/nauthilus
      - ./lua-plugins.d:/etc/nauthilus/lua-plugins.d
    environment:
      - TZ=Europe/Berlin
      - NAUTHILUS_EXPERIMENTAL_ML=true
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

Save this configuration in a file named `docker-compose.yml` and start the services with:

```bash
docker compose up -d
```

#### Manual Installation

1. Clone the repository:

```bash
git clone https://github.com/croessner/nauthilus.git
cd nauthilus
```

2. Compile the project:

```bash
make build
```

3. Install the binary:

```bash
sudo make install
```

### Configuration

The main configuration file is located at `/etc/nauthilus/nauthilus.yml`. Here is an example of a basic configuration:

```yaml
server:
  address: "0.0.0.0:8080"
  instance_name: "nauthilus"
  log:
    level: "info"
    json: true
  backends: [ cache, ldap, lua ]
  features: [ brute_force, tls_encryption, rbl, relay_domains, lua ]

  redis:
    master:
      address: "localhost:6379"
    database_number: 0
    prefix: nt_
    pool_size: 10
    positive_cache_ttl: 3600
    negative_cache_ttl: 7200

ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 4
    lookup_idle_pool_size: 1
    auth_pool_size: 4
    auth_idle_pool_size: 2
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: true
    bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
    bind_pw: "secret"
```

### Advanced Configuration Options

#### TLS Configuration

For secure communication, you can enable TLS:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/etc/nauthilus/ssl/certs/tls.crt"
    key_file: "/etc/nauthilus/ssl/private/tls.key"
    http_client_skip_verify: true
```

#### Brute Force Detection

Nauthilus offers protection against brute force attacks:

```yaml
brute_force:
  ip_whitelist:
    - 127.0.0.0/8
    - ::1
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - fd00::/8
    - 169.254.0.0/16
    - fe80::/10

  neural_network:
    max_training_records: 30000
    hidden_neurons: 20
    activation_function: relu

  tolerate_percent: 3
  tolerate_ttl: 30m

  buckets:
    - { name: b_1m_ipv4_32,  period: 1m,   cidr: 32, ipv4: true, failed_requests: 10 }
    - { name: b_1h_ipv4_24,  period: 1h,   cidr: 24, ipv4: true, failed_requests: 15 }
    - { name: b_1d_ipv4_24,  period: 24h,  cidr: 24, ipv4: true, failed_requests: 25 }
    - { name: b_1w_ipv4_24,  period: 168h, cidr: 24, ipv4: true, failed_requests: 40 }

    - { name: b_1m_ipv6_128, period: 1m,   cidr: 128, ipv6: true, failed_requests: 10 }
    - { name: b_1h_ipv6_64,  period: 1h,   cidr: 64,  ipv6: true, failed_requests: 15 }
    - { name: b_1d_ipv6_64,  period: 24h,  cidr: 64,  ipv6: true, failed_requests: 25 }
    - { name: b_1w_ipv6_64,  period: 168h, cidr: 64,  ipv6: true, failed_requests: 40 }
```

> **Note:** Using the neural network for brute force detection requires that the environment variable `NAUTHILUS_EXPERIMENTAL_ML` is set to `true`.

#### Multiple LDAP Pools

You can configure multiple LDAP pools for different domains:

```yaml
ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 4
    lookup_idle_pool_size: 1
    auth_pool_size: 4
    auth_idle_pool_size: 2
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: true
    bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
    bind_pw: "secret"

  optional_ldap_pools:
    mail:
      number_of_workers: 100
      lookup_pool_size: 8
      lookup_idle_pool_size: 4
      auth_pool_size: 16
      auth_idle_pool_size: 5
      server_uri: "ldaps://ldap.mail.example.com:636/"
      tls_skip_verify: true
      sasl_external: false
      tls_ca_cert: "/etc/nauthilus/ssl/certs/ca.crt"
      bind_dn: "cn=authserv,ou=people,ou=it,dc=example,dc=com"
      bind_pw: "secret2"

  search:
    - protocol: [ default, http ]
      cache_name: http
      base_dn: "ou=people,ou=it,dc=example,dc=com"
      filter:
        user: |
          (|
            (uniqueIdentifier=%L{user})
            (mail=%L{user})
          )
      mapping:
        account_field: mail
      attribute: mail
```

### Troubleshooting Installation

#### Redis Connection Problems

If Nauthilus cannot connect to Redis, check:

1. If Redis is running: `redis-cli ping` should return `PONG`
2. The Redis configuration in `nauthilus.yml`
3. Firewall settings that might block access to Redis

#### LDAP Connection Problems

For problems with the LDAP connection:

1. Test the LDAP connection with `ldapsearch`
2. Check the LDAP configuration in `nauthilus.yml`
3. Make sure the LDAP server is reachable
4. Check the bind DN and password

#### Logging Problems

If you have problems with logging:

1. Set the log level to `debug` for more detailed information
2. Check the permissions of the log directory
3. Make sure there is enough disk space

## Lua Backends

Nauthilus allows the implementation of custom authentication backends in Lua. These backends can interact with various data sources, such as databases or APIs.

### Basic Concepts

A Lua backend consists of at least one of the following functions:

- `nauthilus_backend_verify_password(request)`: Verifies user credentials
- `nauthilus_backend_list_accounts()`: Lists available accounts

### Example: MySQL Backend

Here is a simple example of a MySQL backend:

```lua
local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_password")
local nauthilus_password = require("nauthilus_password")

dynamic_loader("nauthilus_gll_db")
local db = require("db")

local config = {
    shared = true,
    max_connections = 100,
    read_only = false,
}

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local mysql, err_open = db.open("mysql", "user:password@tcp(127.0.0.1)/database", config)
    nauthilus_util.if_error_raise(err_open)

    local result, err_query = mysql:query(
        "SELECT account, password FROM users WHERE username = \"" .. request.username .. "\";"
    )
    nauthilus_util.if_error_raise(err_query)

    local attributes = {}

    for _, row in pairs(result.rows) do
        for id, name in pairs(result.columns) do
            if name == "password" then
                if not request.no_auth then
                    local match, err = nauthilus_password.compare_passwords(row[id], request.password)
                    nauthilus_util.if_error_raise(err)

                    b:authenticated(match)
                end
            else
                if name == "account" then
                    b:account_field("account")
                    b:user_found(true)
                end

                attributes[name] = row[id]
            end
        end
    end

    b:attributes(attributes)

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end
```

This script defines a function `nauthilus_backend_verify_password` that takes a user request, performs a database query, and returns the result. It checks the password and sets various attributes in the result object.

### Advanced Example: Backend with Additional Attributes

Here is an advanced example that processes additional user attributes:

```lua
function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local mysql, err_open = db.open("mysql", "user:password@tcp(127.0.0.1)/database", config)
    nauthilus_util.if_error_raise(err_open)

    local result, err_query = mysql:query(
        "SELECT account, password, uniqueid, display_name FROM users WHERE username = \"" .. request.username .. "\" OR account = \"" .. request.username .. "\";"
    )
    nauthilus_util.if_error_raise(err_query)

    local attributes = {}

    for _, row in pairs(result.rows) do
        for id, name in pairs(result.columns) do
            if name == "password" then
                if not request.no_auth then
                    local match, err = nauthilus_password.compare_passwords(row[id], request.password)
                    nauthilus_util.if_error_raise(err)

                    b:authenticated(match)
                end
            else
                if name == "account" then
                    b:account_field("account")
                    b:user_found(true)
                end

                if name == "uniqueid" and row[id] ~= "" then
                    b:unique_user_id_field("uniqueid")
                end

                if name == "display_name" and row[id] ~= "" then
                    b:display_name_field("display_name")
                end

                attributes[name] = row[id]
            end
        end
    end

    b:attributes(attributes)

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end
```

### Available Functions in the Backend Context

The following functions and objects are available in the backend context:

#### nauthilus_backend_result

The `nauthilus_backend_result` object provides methods for setting result attributes:

- `new()`: Creates a new result object
- `authenticated(bool)`: Sets the authentication status
- `user_found(bool)`: Indicates whether the user was found
- `account_field(string)`: Sets the field for the account name
- `unique_user_id_field(string)`: Sets the field for the unique user ID
- `display_name_field(string)`: Sets the field for the display name
- `attributes(table)`: Sets additional attributes

#### request Object

The `request` object contains information about the authentication request:

- `username`: The username from the request
- `password`: The password from the request
- `protocol`: The protocol used (e.g., "dovecot", "nginx")
- `client_ip`: The client's IP address
- `no_auth`: Flag indicating whether authentication is required

### Setting Up a Lua Backend

1. Create a directory for your backend:

```bash
mkdir -p /etc/nauthilus/lua-plugins.d/backend
```

2. Create your backend file, e.g., `mysql.lua`:

```bash
vim /etc/nauthilus/lua-plugins.d/backend/mysql.lua
```

3. Add your Lua code and save the file.

4. Update your Nauthilus configuration to enable the Lua backend:

```yaml
server:
  backends:
    - lua
```

### Exercise: Create a Simple Lua Backend

In this exercise, we'll create a simple Lua backend that authenticates users against a hardcoded list.

1. Create a file `/etc/nauthilus/lua-plugins.d/backend/simple.lua`:

```lua
local nauthilus_util = require("nauthilus_util")

-- Hardcoded user list (in practice, you would use a database)
local users = {
    ["user1"] = {password = "password1", account = "user1@example.com"},
    ["user2"] = {password = "password2", account = "user2@example.com"}
}

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local user = users[request.username]

    if user then
        b:user_found(true)
        b:account_field("account")

        if not request.no_auth then
            b:authenticated(user.password == request.password)
        end

        b:attributes({account = user.account})
    else
        b:user_found(false)
        b:authenticated(false)
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end

function nauthilus_backend_list_accounts()
    local accounts = {}

    for _, user in pairs(users) do
        table.insert(accounts, user.account)
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, accounts
end
```

2. Update your Nauthilus configuration:

```yaml
server:
  backends:
    - lua
```

3. Restart Nauthilus:

```bash
# If you're using Docker Compose:
docker compose restart nauthilus

# If you're using Docker directly:
docker restart nauthilus
```

4. Test the authentication:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Lua Filters

Filters in Nauthilus are used to process authentication requests and decide whether they should be accepted or rejected. Filters can be implemented in Lua to add custom logic.

### Basic Concepts

A Lua filter consists of a function `nauthilus_call_filter(request)` that takes a request and decides whether it should be accepted or rejected. The function returns two values:

1. A decision: `FILTER_ACCEPT` or `FILTER_REJECT`
2. A result: `FILTER_RESULT_OK` or `FILTER_RESULT_FAIL`

### Example: Simple Filter

Here is a simple example of a filter that filters requests based on the IP address:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Check if the IP is routable
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Early termination for non-routable addresses
    if not is_routable then
        if request.authenticated then
            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
        else
            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- Additional filter logic could go here

    -- The request should only be accepted if it was authenticated
    if request.authenticated then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    else
        return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
    end
end
```

This filter checks if the client's IP address is routable and decides accordingly whether the request should be accepted or rejected.

### Advanced Example: Geolocation Filter

Here is an advanced example of a filter that filters requests based on geographic location:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Check if the IP is routable
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Early termination for non-routable addresses
    if not is_routable then
        if request.authenticated then
            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
        else
            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    if request.authenticated then
        dynamic_loader("nauthilus_gluahttp")
        local http = require("glua_http")

        dynamic_loader("nauthilus_gll_json")
        local json = require("json")

        local t = {}

        t.key = "client"
        t.value = {
            address = request.client_ip,
            sender = request.account
        }

        local payload, json_encode_err = json.encode(t)
        nauthilus_util.if_error_raise(json_encode_err)

        -- Sending a request to a geolocation service
        local result, request_err = http.post("https://geoip.example.com/check", {
            timeout = "10s",
            headers = {
                Accept = "*/*",
                ["User-Agent"] = "Nauthilus",
                ["Content-Type"] = "application/json",
            },
            body = payload,
        })
        nauthilus_util.if_error_raise(request_err)

        local response, err_jdec = json.decode(result.body)
        nauthilus_util.if_error_raise(err_jdec)

        -- Check if the country is on the blocklist
        if response.country_code and response.country_code == "XY" then
            nauthilus_builtin.custom_log_add("geoip_blocked_country", response.country_code)
            nauthilus_builtin.status_message_set("Access from this country not allowed")

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    else
        -- Reject unauthenticated requests
        return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- The request should be accepted
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
```

This filter sends a request to a geolocation service to determine the client's location and rejects requests from certain countries.

### Available Functions in the Filter Context

The following functions and objects are available in the filter context:

#### nauthilus_builtin

The `nauthilus_builtin` object provides constants and functions for filters:

- `FILTER_ACCEPT`: Constant for accepting a request
- `FILTER_REJECT`: Constant for rejecting a request
- `FILTER_RESULT_OK`: Constant for a successful filter result
- `FILTER_RESULT_FAIL`: Constant for a failed filter result
- `custom_log_add(key, value)`: Adds a custom log entry
- `status_message_set(message)`: Sets a status message

#### request Object

The `request` object contains information about the authentication request:

- `username`: The username from the request
- `account`: The authenticated account (after successful authentication)
- `authenticated`: Flag indicating whether the request was authenticated
- `protocol`: The protocol used (e.g., "dovecot", "nginx")
- `client_ip`: The client's IP address
- `no_auth`: Flag indicating whether authentication is required
- `session`: The session ID (if available)
- `user_agent`: The client's user agent (if available)
- `client_id`: The client ID (if available)
- `debug`: Flag indicating whether debug mode is enabled
- `log_format`: The format for log output

### Setting Up a Lua Filter

1. Create a directory for your filter:

```bash
mkdir -p /etc/nauthilus/lua-plugins.d/filters
```

2. Create your filter file, e.g., `ip_filter.lua`:

```bash
vim /etc/nauthilus/lua-plugins.d/filters/ip_filter.lua
```

3. Add your Lua code and save the file.

4. Update your Nauthilus configuration to enable the Lua filter:

```yaml
lua:
  filters:
    - name: "ip_filter"
      script_path: "/etc/nauthilus/lua-plugins.d/filters/ip_filter.lua"
```

### Exercise: Create a Simple IP Filter

In this exercise, we'll create a simple filter that blocks requests from specific IP addresses.

1. Create a file `/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua`:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- List of blocked IP addresses
    local blocked_ips = {
        "192.168.1.100",
        "10.0.0.50"
    }

    -- Check if the client IP is in the blocklist
    for _, ip in ipairs(blocked_ips) do
        if request.client_ip == ip then
            nauthilus_builtin.custom_log_add("blocked_ip", request.client_ip)
            nauthilus_builtin.status_message_set("IP address blocked")

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- The request should be accepted
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
```

2. Update your Nauthilus configuration:

```yaml
lua:
  filters:
    - name: "ip_blocklist"
      script_path: "/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua"
```

3. Restart Nauthilus:

```bash
# If you're using Docker Compose:
docker compose restart nauthilus

# If you're using Docker directly:
docker restart nauthilus
```

4. Test the filter:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"192.168.1.100","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Lua Features

Features in Nauthilus are extensions that provide additional functionality. They can be implemented in Lua to add custom logic.

### Basic Concepts

A Lua feature consists of a function `nauthilus_call_feature(request)` that takes a request and provides additional functionality. The function returns three values:

1. A trigger flag: `FEATURE_TRIGGER_YES` or `FEATURE_TRIGGER_NO`
2. An abort flag: `FEATURES_ABORT_YES` or `FEATURES_ABORT_NO`
3. A result: `FEATURE_RESULT_OK` or `FEATURE_RESULT_FAIL`

### Setting Up a Lua Feature

1. Create a directory for your feature:

```bash
mkdir -p /etc/nauthilus/lua-plugins.d/features
```

2. Create your feature file, e.g., `blocklist.lua`:

```bash
vim /etc/nauthilus/lua-plugins.d/features/blocklist.lua
```

3. Add your Lua code and save the file.

4. Update your Nauthilus configuration to enable the Lua feature:

```yaml
lua:
  features:
    - name: "blocklist"
      script_path: "/etc/nauthilus/lua-plugins.d/features/blocklist.lua"
```

### Example: Blocklist Feature

Here is an example of a feature that checks if an IP address is on a blocklist:

```lua
function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_gluahttp")
    local http = require("glua_http")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    local t = {}
    t.ip = request.client_ip

    local payload, json_encode_err = json.encode(t)
    nauthilus_util.if_error_raise(json_encode_err)

    local result, request_err = http.post("https://blocklist.example.com/check", {
        timeout = "10s",
        headers = {
            Accept = "*/*",
            ["User-Agent"] = "Nauthilus",
            ["Content-Type"] = "application/json",
        },
        body = payload,
    })
    nauthilus_util.if_error_raise(request_err)

    if result.status_code ~= 200 then
        nauthilus_util.if_error_raise("blocklist_status_code=" .. tostring(result.status_code))
    end

    local response, err_jdec = json.decode(result.body)
    nauthilus_util.if_error_raise(err_jdec)

    if response.found then
        nauthilus_builtin.custom_log_add("blocklist_ip", request.client_ip)
        nauthilus_builtin.status_message_set("IP address blocked")

        return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_YES, nauthilus_builtin.FEATURE_RESULT_OK
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
```

This feature sends a request to a blocklist service to check if the client's IP address is on a blocklist. If so, the request is rejected.

### Advanced Example: Neural Network Feature with ipapi.com

> **Note:** To use the neural network functions, the environment variable `NAUTHILUS_EXPERIMENTAL_ML` must be set to `true`. Without this setting, the ML functions will not be initialized.

> **Note on API:** To use ipapi.com, you need an API key. You can register for free on [ipapi.com](https://ipapi.com/) to get a free API key. The free plan offers a limited number of requests per month, which is sufficient for testing purposes.

> **Important:** This example uses Prometheus metrics that must be initialized in an init.lua file before the script can be executed. Without this initialization, the script will fail with an error. Here is an example of an init.lua file that initializes the required Prometheus vectors:

```lua
-- init.lua
function nauthilus_run_hook(logging)
    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    -- Initialization of the gauge vector for HTTP client requests
    nauthilus_prometheus.create_gauge_vec("http_client_concurrent_requests_total", "Measure the number of total concurrent HTTP client requests", { "service" })

    -- Initialization of the histogram vector for ipapi requests
    nauthilus_prometheus.create_histogram_vec("ipapi_duration_seconds", "HTTP request to the ipapi service", { "http" })

    local result = {
        level = "info",
        caller = "init.lua",
        status = "finished"
    }

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end
end
```

Here is an advanced example that uses ipapi.com to collect geolocation data and normalize it for the neural network:

```lua
function nauthilus_call_neural_network(request)
    if request.no_auth then
        return
    end

    local nauthilus_util = require("nauthilus_util")

    -- Check if the IP is routable
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Early termination for non-routable addresses
    if not is_routable then
        return
    end

    local logs = {}
    logs.caller = "ipapi.lua"
    logs.level = "info"

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    dynamic_loader("nauthilus_gluahttp")
    local http = require("glua_http")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    -- Prometheus metrics for HTTP requests
    local HCCR = "http_client_concurrent_requests_total"
    nauthilus_prometheus.increment_gauge(HCCR, { service = "ipapi" })

    -- Send request to ipapi.com
    local timer = nauthilus_prometheus.start_histogram_timer("ipapi_duration_seconds", { http = "get" })
    local api_key = os.getenv("IPAPI_API_KEY") or "YOUR_API_KEY_HERE"
    local result, request_err = http.get("http://api.ipapi.com/api/" .. request.client_ip .. "?access_key=" .. api_key, {
        timeout = "5s",
        headers = {
            Accept = "*/*",
            ["User-Agent"] = "Nauthilus",
        }
    })

    nauthilus_prometheus.stop_timer(timer)
    nauthilus_prometheus.decrement_gauge(HCCR, { service = "ipapi" })
    nauthilus_util.if_error_raise(request_err)

    if result.status_code ~= 200 then
        nauthilus_util.if_error_raise("ipapi_status_code=" .. tostring(result.status_code))
    end

    local response, err_jdec = json.decode(result.body)
    nauthilus_util.if_error_raise(err_jdec)

    if response.error == nil then
        -- Extract and normalize data for the neural network
        local features = {}

        -- Country and continent as categorical features
        features.country_code = response.country_code or "unknown"
        features.continent_code = response.continent_code or "unknown"

        -- Normalize numeric features to [0, 1]

        -- Normalize latitude: from [-90, 90] to [0, 1]
        if response.latitude then
            features.latitude_normalized = (response.latitude + 90) / 180
        end

        -- Normalize longitude: from [-180, 180] to [0, 1]
        if response.longitude then
            features.longitude_normalized = (response.longitude + 180) / 360
        end

        -- Normalize timezone: from [-12, 14] to [0, 1]
        if response.timezone and response.timezone.gmt_offset then
            features.timezone_normalized = (response.timezone.gmt_offset + 12) / 26
        end

        -- Normalize security rating (if available): from [0, 100] to [0, 1]
        if response.security and response.security.threat_score then
            features.threat_score_normalized = response.security.threat_score / 100
        end

        -- ASN number as categorical feature
        if response.connection and response.connection.asn then
            features.asn = "AS" .. tostring(response.connection.asn)
        end

        -- Connection type as categorical feature
        if response.connection and response.connection.type then
            features.connection_type = response.connection.type
        end

        -- Logs for debugging
        for k, v in pairs(features) do
            logs[k] = v
            nauthilus_builtin.custom_log_add("ipapi_" .. k, tostring(v))
        end

        -- Output logs
        nauthilus_util.print_result({ log_format = "json" }, logs)

        -- Add to neural network
        dynamic_loader("nauthilus_neural")
        local nauthilus_neural = require("nauthilus_neural")
        nauthilus_neural.add_additional_features(features)
    end

    return
end
```

This advanced example shows how to retrieve data from ipapi.com and prepare it for the neural network:

1. **Retrieving Geolocation Data**: The function sends a request to ipapi.com to get information about the client's IP address.

2. **Normalizing Numeric Values**: Numeric values such as latitude, longitude, and timezone are normalized to the range [0, 1] so they can be effectively processed by the neural network:
   - Latitude: from [-90, 90] to [0, 1]
   - Longitude: from [-180, 180] to [0, 1]
   - Timezone: from [-12, 14] to [0, 1]
   - Security rating: from [0, 100] to [0, 1]

3. **Categorical Features**: Values such as country code, continent code, ASN number, and connection type are added as categorical features. These are automatically processed by the neural network using one-hot encoding.

4. **Logging and Metrics**: The function logs all extracted features and measures the duration of the API request with Prometheus metrics.

Normalization to the range [0, 1] is important because neural networks work best with input values in a consistent range. Normalization ensures that no feature is overweighted due to its magnitude.


### Available Functions in the Feature Context (nauthilus_call_feature)

The following functions and objects are only available in the context of features that implement the `nauthilus_call_feature` function:

#### nauthilus_builtin

The `nauthilus_builtin` object provides constants and functions for features:

- `FEATURE_TRIGGER_YES`: Constant for triggering a feature
- `FEATURE_TRIGGER_NO`: Constant for not triggering a feature
- `FEATURES_ABORT_YES`: Constant for aborting feature processing
- `FEATURES_ABORT_NO`: Constant for continuing feature processing
- `FEATURE_RESULT_OK`: Constant for a successful feature result
- `FEATURE_RESULT_FAIL`: Constant for a failed feature result
- `custom_log_add(key, value)`: Adds a custom log entry
- `status_message_set(message)`: Sets a status message

#### request Object

The `request` object contains information about the authentication request, similar to the filter context.

### Available Functions in the Neural Network Context (nauthilus_call_neural_network)

For features that implement the `nauthilus_call_neural_network` function, different functions are available:

#### nauthilus_builtin

The `nauthilus_builtin` object provides only the following functions in this context:

- `custom_log_add(key, value)`: Adds a custom log entry

#### nauthilus_neural

The `nauthilus_neural` object provides functions for interacting with the neural network:

- `add_additional_features(features)`: Adds additional features to the neural network

#### request Object

The `request` object contains information about the authentication request, similar to the feature context.

> **Note:** Unlike `nauthilus_call_feature`, the `nauthilus_call_neural_network` function does not return any values. It is only used to collect additional features for the neural network.

### Exercise: Create a Simple Logging Feature

In this exercise, we'll create a simple feature that logs authentication attempts.

1. Create a file `/etc/nauthilus/lua-plugins.d/features/logging.lua`:

```lua
function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Log the authentication attempt
    nauthilus_builtin.custom_log_add("auth_attempt_username", request.username)
    nauthilus_builtin.custom_log_add("auth_attempt_ip", request.client_ip)
    nauthilus_builtin.custom_log_add("auth_attempt_protocol", request.protocol)

    if request.user_agent then
        nauthilus_builtin.custom_log_add("auth_attempt_user_agent", request.user_agent)
    end

    -- Trigger feature but continue processing
    return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
```

2. Update your Nauthilus configuration:

```yaml
lua:
  features:
    - name: "logging"
      script_path: "/etc/nauthilus/lua-plugins.d/features/logging.lua"
```

3. Restart Nauthilus:

```bash
# If you're using Docker Compose:
docker-compose restart nauthilus

# If you're using Docker directly:
docker restart nauthilus
```

4. Test the feature:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Monitoring and Debugging

Nauthilus offers various options for monitoring and debugging:

### Prometheus Metrics

Nauthilus exports metrics in Prometheus format. These can be collected with Prometheus and visualized with Grafana.

Enable Prometheus metrics in your configuration:

```yaml
server:
   prometheus_timer:
     enabled: true
     labels: [ backend, filter, action, post_action, request, feature, brute_force, dns ]
```

#### Important Metrics

Nauthilus exports various metrics, including:

- `nauthilus_http_requests_total`: Total number of HTTP requests
- `nauthilus_authentication_attempts_total`: Total number of authentication attempts
- `nauthilus_authentication_success_total`: Total number of successful authentications
- `nauthilus_authentication_failure_total`: Total number of failed authentications
- `nauthilus_backend_request_duration_seconds`: Duration of backend requests
- `nauthilus_filter_duration_seconds`: Duration of filter processing
- `nauthilus_feature_duration_seconds`: Duration of feature processing

### Grafana Dashboard

Nauthilus provides a pre-made Grafana dashboard that you can import:

1. Install Grafana:

```bash
docker run -d --name grafana -p 3000:3000 grafana/grafana
```

2. Configure a Prometheus data source in Grafana.

3. Import the Nauthilus dashboard from the repository:

```
/path/to/nauthilus/contrib/grafana/dashboard.json
```

### Logging

Nauthilus supports various log levels and formats:

```yaml
server:
  log:
    level: "debug"  # Options: debug, info, warn, error
    json: true
    color: true
```

#### Log Levels

- `debug`: Detailed debugging information
- `info`: Informational messages
- `warn`: Warnings
- `error`: Error messages

#### Log Formats

- `true`: **json**: Structured logs in JSON format
- `false`: **text**: Human-readable logs in text format

### Debugging Lua Scripts

For debugging Lua scripts, you can use the `print` function, which writes output to the Nauthilus logs:

```lua
nauthilus_util.print_result({ log_format = "json" }, { message = "Debug message", level = "debug" })
```

You can also add custom log entries:

```lua
nauthilus_builtin.custom_log_add("debug_key", "debug_value")
```

### Exercise: Set Up Monitoring

In this exercise, we'll set up Prometheus and Grafana for monitoring Nauthilus.

1. Create a Docker Compose file for Prometheus and Grafana:

```yaml
version: '3'

services:
  nauthilus:
    image: ghcr.io/croessner/nauthilus:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/nauthilus
      - ./lua-plugins.d:/etc/nauthilus/lua-plugins.d
    environment:
      - TZ=Europe/Berlin
      - NAUTHILUS_EXPERIMENTAL_ML=true
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus:/etc/prometheus
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
    restart: unless-stopped

  grafana:
    image: grafana/grafana
    environment:
       # GF_INSTALL_PLUGINS: "grafana-piechart-panel,grafana-worldmap-panel,grafana-clickhouse-datasource,alexanderzobnin-zabbix-app"
       GF_FEATURE_TOGGLES_ENABLE: "featureToggleAdminPage,regressionTransformation"
       GF_FEATURE_MANAGEMENT_ALLOW_EDITING: "true"
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - prometheus
    restart: unless-stopped

volumes:
  redis-data:
  prometheus-data:
  grafana-data:
```

2. Create a Prometheus configuration file `prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'nauthilus'
    static_configs:
      - targets: ['nauthilus:8080']
    metrics_path: /metrics
```

3. Start the services:

```bash
docker compose up -d
```

4. Open Grafana at http://localhost:3000 (default credentials: admin/admin).

5. Add Prometheus as a data source (URL: http://prometheus:9090).

6. Import the Nauthilus dashboard.

## Post-Actions

Post-Actions in Nauthilus are Lua scripts that are executed asynchronously after the main processing of an authentication request is completed. They allow additional actions to be performed without affecting the response time of the main request.

### Basic Concepts

Post-Actions are defined in the configuration under the `lua.actions` section:

```yaml
lua:
  actions:
    - type: post
      name: "Logging"
      script_path: "/etc/nauthilus/lua-plugins.d/actions/logging.lua"
    - type: post
      name: "Notification"
      script_path: "/etc/nauthilus/lua-plugins.d/actions/notification.lua"
```

Each Post-Action has a type (`post`), a name, and a path to the Lua script. The script is executed asynchronously after the response has been sent to the client.

### Example: Logging Post-Action

Here is a simple example of a Post-Action that logs successful and failed login attempts:

```lua
function nauthilus_run_hook(logging)
    local nauthilus_util = require("nauthilus_util")

    local result = {}
    result.level = "info"
    result.caller = "logging.lua"

    -- Log authentication attempt
    if request.authenticated then
        result.message = "Successful login"
        result.status = "success"
    else
        result.message = "Failed login"
        result.status = "failure"
    end

    result.username = request.username
    result.client_ip = request.client_ip
    result.timestamp = nauthilus_util.get_current_timestamp()

    -- Output the result
    nauthilus_util.print_result(logging, result)
end
```

## Custom Hooks

Custom Hooks in Nauthilus allow the creation of custom HTTP endpoints with their own logic. They are called via special URLs and can be used for various purposes.

### Basic Concepts

Custom Hooks are defined in the configuration under the `lua.custom_hooks` section:

```yaml
lua:
  custom_hooks:
    - http_location: "/postfix/map"
      http_method: POST
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/postfix_map.lua"
    - http_location: "/status/check"
      http_method: GET
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/status_check.lua"
```

Each Custom Hook has an HTTP path (`http_location`), an HTTP method (`http_method`), and a path to the Lua script. The script is executed when the corresponding endpoint is called.

### Example: Status Check Hook

Here is a simple example of a Custom Hook that checks the status of the system:

```lua
function nauthilus_run_hook(logging)
    local nauthilus_util = require("nauthilus_util")

    -- Check Redis connection
    dynamic_loader("nauthilus_redis")
    local nauthilus_redis = require("nauthilus_redis")

    local redis_status = "ok"
    local _, err_redis = nauthilus_redis.redis_ping("default")
    if err_redis then
        redis_status = "error: " .. err_redis
    end

    -- Create status report
    local status = {
        status = "ok",
        components = {
            redis = redis_status,
            server = "ok"
        },
        timestamp = nauthilus_util.get_current_timestamp()
    }

    return status
end
```

This hook returns a JSON status when the endpoint `/api/v1/custom/status/check` is called with the GET method.

## Advanced Topics

### Load Balancing and High Availability

Nauthilus can be operated in a high availability environment by deploying multiple instances behind a load balancer:

```
                    +----------------+
                    |                |
                    | Load Balancer  |
                    |                |
                    +-------+--------+
                            |
            +---------------+---------------+
            |               |               |
  +---------v-----+  +------v------+  +-----v-------+
  |               |  |             |  |             |
  | Nauthilus 1   |  | Nauthilus 2 |  | Nauthilus 3 |
  |               |  |             |  |             |
  +-------+-------+  +------+------+  +------+------+
          |                 |                |
          +--------+--------+--------+-------+
                   |                 |
         +---------v---------+ +-----v-----------+
         |                   | |                 |
         | Redis Cluster     | | LDAP/Database   |
         |                   | |                 |
         +-------------------+ +-----------------+
```

Configure Redis for session persistence:

```yaml
redis:
  # If Redis runs on 127.0.0.1:6379, no configuration is necessary
  # For other targets, master: and replica: must be configured
  master:
    address: "redis-master:6379"

  replica:
    addresses:
      - "redis-replica:6379"
```

### Security Recommendations

#### TLS Configuration

Use TLS for communication:

```yaml
server:
  tls:
    enabled: true
    cert: "/etc/nauthilus/cert.pem"
    key: "/etc/nauthilus/key.pem"
```

#### Secure Redis Configuration

Protect Redis with a password and use clusters or sentinels for high availability:

```yaml
redis:
  pool_size: 30
  idle_pool_size: 20
  database_number: 0
  prefix: nt_

  # Option 1: Master/Replica with password
  master:
    address: "redis-master:6379"
    username: "redis-user"
    password: "secure-password"

  # Option 2: Redis Sentinel
  sentinels:
    master: "myMaster"
    addresses:
      - "redis-sentinel-1:26379"
      - "redis-sentinel-2:26379"
    username: "sentinel-user"
    password: "secure-password"

  # Option 3: Redis Cluster
  cluster:
    addresses:
      - "redis-node-1:6379"
      - "redis-node-2:6379"
      - "redis-node-3:6379"
```

#### Secure LDAP Configuration

Use TLS for the LDAP connection:

```yaml
ldap:
  config:
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: false
    sasl_external: true
    tls_ca_cert: "/etc/nauthilus/ssl/certs/ca.crt"
    tls_client_cert: "/etc/nauthilus/ssl/certs/tls.crt"
    tls_client_key: "/etc/nauthilus/ssl/private/tls.key"
```

#### HTTP Basic Authentication

Protect Nauthilus's API endpoints with HTTP Basic Authentication:

```yaml
server:
  basic_auth:
    enabled: true
    username: authserv
    password: secure-password
```

This configuration enables HTTP Basic Authentication for all API endpoints under `/api/v1`. Clients must provide valid credentials to access these endpoints. If only `enabled: true` is specified, username and password must be provided via environment variables or other configuration mechanisms.

HTTP Basic Authentication provides a simple but effective method to prevent unauthorized access to your Nauthilus API. It is recommended to enable this feature in production environments and use a secure password.

> **Note:** Always use HTTP Basic Authentication in combination with TLS, as otherwise the credentials are transmitted in plain text.

### Performance Optimization

#### Redis Optimization

Optimize the Redis configuration for better performance:

```yaml
redis:
  pool_size: 30
  idle_pool_size: 20
  database_number: 0
  prefix: nt_
  positive_cache_ttl: 3600
  negative_cache_ttl: 7200
```

#### LDAP Connection Pooling

Optimize LDAP connection pooling:

```yaml
ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 8
    lookup_idle_pool_size: 4
    auth_pool_size: 16
    auth_idle_pool_size: 5
```

#### Lua Script Optimization

Optimize your Lua scripts for better performance:

- Avoid unnecessary HTTP requests
- Use caching where possible
- Minimize the number of dynamically loaded modules

### Troubleshooting

#### Common Problems and Solutions

1. **Redis Connection Problems**:
   - Check the Redis configuration
   - Make sure Redis is running
   - Check firewall settings

2. **LDAP Connection Problems**:
   - Check the LDAP configuration
   - Test the LDAP connection with `ldapsearch`
   - Check firewall settings

3. **Lua Script Errors**:
   - Check the syntax of your Lua scripts
   - Add debugging output
   - Check the Nauthilus logs for error messages

4. **Performance Problems**:
   - Check the Redis performance
   - Optimize your Lua scripts
   - Increase the number of Nauthilus instances

## Example Applications

### Authentication for a Mail Server

Here is an example of configuring Nauthilus for authentication for a Postfix/Dovecot mail server:

1. Configure Nauthilus with an LDAP backend:

```yaml
server:
  backends:
    - ldap

ldap:
   config:
      number_of_workers: 100

      lookup_pool_size: 8
      lookup_idle_pool_size: 4

      auth_pool_size: 16
      auth_idle_pool_size: 5

      server_uri:
         - "ldap.example.com:389"
      bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
      bind_pw: "geheim"

   search:
      - protocol: http
        cache_name: http
        base_dn: "dc=example,dc=com"
        filter:
           user: "(&(objectClass=person)(uid=%L{user}))"
        mapping:
           account_field: "uid"
        attributes:
           - uid
```

2. Configure Postfix for authentication via Nauthilus:

```
# /etc/postfix/main.cf
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
```

3. Configure Dovecot for authentication via Nauthilus:

```
# /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login
passdb {
  driver = lua
  args = file=/etc/dovecot/auth-nauthilus.lua
}
userdb {
  driver = lua
  args = file=/etc/dovecot/auth-nauthilus.lua
}
```

Create the Lua script file for authentication:

```lua
-- dovecot-auth.lua
--
-- Example script for Dovecot authentication with Nauthilus

--
-- START Settings
--

-- Enable/disable debug mode for HTTP requests
local http_debug = false;
-- Path to the file with the HTTP Basic Auth password
local http_basicauthfile = "/etc/dovecot/http-auth.secret"
-- URL to the Nauthilus API endpoint (replace this with your actual Nauthilus URL)
local http_uri = "https://example.com/api/v1/auth/json"
-- Message displayed when an account is disabled
local http_access_denied = "Account not enabled"

--
-- END Settings
--

-- JSON library for processing requests and responses
local json = require('cjson')

-- Constants for distinguishing between password and user queries
local PASSDB = "passdb"
local USERDB = "userdb"

-- HTTP client configuration
local http_basicauthpassword -- Will be read from the file in init_http()
local http_client = dovecot.http.client{
    timeout = 300;           -- Timeout in seconds
    max_attempts = 3;        -- Number of retry attempts
    debug = http_debug;      -- Debug mode from settings
    user_agent = "Dovecot/2.3"; -- User-Agent header
}

-- Function to initialize HTTP authentication
-- Reads the password for HTTP Basic Auth from the configured file
local function init_http()
    -- Open the file with the password
    local file = assert (io.open(http_basicauthfile))

    -- Read the content of the file (Base64-encoded password)
    http_basicauthpassword = file:read("*all")

    -- Close the file
    file:close()
end

-- Main function for communication with Nauthilus
-- Parameters:
--   request: Dovecot request object with user information
--   password: User's password (empty for userdb queries)
--   dbtype: Type of request (PASSDB or USERDB)
-- Returns:
--   Dovecot authentication result and additional fields
local function query_db(request, password, dbtype)
    -- Extract connection information from the request
    local remote_ip = request.remote_ip       -- Client's IP address
    local remote_port = request.remote_port   -- Client's port
    local local_ip = request.local_ip         -- Server's local IP address
    local local_port = request.local_port     -- Server's local port
    local client_id = request.client_id       -- Client ID (if available)
    local qs_noauth = ""                      -- Query string for no-auth mode
    local extra_fields = {}                   -- Additional fields for the response

    -- Helper function to add fields to the response
    -- pf: Prefix for the field (e.g., "userdb_")
    -- key: Field key
    -- value: Field value
    local function add_extra_field(pf, key, value)
        if value ~= nil and value:len()>0 then
            extra_fields[pf .. key] = value
        end
    end

    -- For userdb queries, the no-auth mode is used
    -- (no password verification, only retrieve user information)
    if dbtype == USERDB then
        qs_noauth = "?mode=no-auth"
    end
    -- Create an HTTP request to the Nauthilus server
    local auth_request = http_client:request {
        url = http_uri .. qs_noauth;  -- URL with optional no-auth parameter
        method = "POST";              -- HTTP method POST for authentication requests
    }

    -- Add HTTP Basic Authentication
    -- The password was previously read from the file
    auth_request:add_header("Authorization", "Basic " .. http_basicauthpassword)

    -- Set the Content-Type header to application/json
    auth_request:add_header("Content-Type", "application/json")

    -- Set default values for missing parameters
    -- This ensures that the request works even if
    -- not all information is available
    if remote_ip == nil then
        remote_ip = "127.0.0.1"  -- Local IP as fallback
    end
    if remote_port == nil then
        remote_port = "0"        -- Default port as fallback
    end
    if local_ip == nil then
        local_ip = "127.0.0.1"   -- Local IP as fallback
    end
    if local_port == nil then
        local_port = "0"         -- Default port as fallback
    end
    if client_id == nil then
        client_id = ""           -- Empty string as fallback
    end

    -- Special handling for master user authentication
    -- A master user can authenticate as another user
    if dbtype == PASSDB then
        -- Check if it's a master user (auth_user != user)
        if request.auth_user:lower() ~= request.user:lower() then
            -- Add the target user to the extra fields
            add_extra_field("", "user", request.user)

            -- Perform a userdb query for the target user
            local userdb_status = query_db(request, "", USERDB)

            -- Handle different results of the userdb query
            if userdb_status == dovecot.auth.USERDB_RESULT_USER_UNKNOWN then
                -- User not found
                return dovecot.auth.PASSDB_RESULT_USER_UNKNOWN, ""
            elseif userdb_status == dovecot.auth.USERDB_RESULT_INTERNAL_FAILURE then
                -- Internal error
                return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, ""
            else
                -- User found, allow access
                return dovecot.auth.PASSDB_RESULT_OK, extra_fields
            end
        end
    end

    -- Create the JSON request object for Nauthilus
    local req = {}

    -- Add all relevant information to the request
    req.username = request.user       -- Username
    req.password = password           -- Password (empty for userdb queries)
    req.client_ip = remote_ip         -- Client's IP address
    req.client_port = remote_port     -- Client's port
    req.client_id = client_id         -- Client ID (if available)
    req.local_ip = local_ip           -- Server's local IP address
    req.local_port = local_port       -- Server's local port
    req.service = request.service     -- Service (imap, pop3, etc.)
    req.method = request.mech:lower() -- Authentication method (plain, login, etc.)

    -- Add TLS information if the connection is secure
    if request.secured == "TLS" or request.secured == "secured" then
        req.ssl = "1"                 -- TLS is enabled
        req.ssl_protocol = request.secured  -- TLS protocol

        -- Add client certificate information if available
        if request.cert ~= "" then
            req.ssl_client_verify = "1"  -- Client certificate was verified
        end
    end

    -- Add session information if available
    if request.session ~= nil then
        auth_request:add_header("X-Dovecot-Session", request.session)
    end

    -- Set the JSON payload for the request
    auth_request:set_payload(json.encode(req))

    -- Send the request to the Nauthilus server
    local auth_response = auth_request:submit()

    -- Process the response
    local auth_status_code = auth_response:status()     -- HTTP status code
    local auth_status_message = auth_response:header("Auth-Status")  -- Authentication status

    -- Extract important headers from the response
    local dovecot_account = auth_response:header("Auth-User")  -- Actual username
    local nauthilus_session = auth_response:header("X-Nauthilus-Session")  -- Session ID

    -- Log the request and response for debugging purposes
    dovecot.i_info("request=" .. dbtype .. " service=" .. request.service .. " user=<" .. request.user ..  "> auth_status_code=" .. tostring(auth_status_code) .. " auth_status_message=<" .. auth_status_message .. "> nauthilus_session=" .. nauthilus_session)

    -- Handle successful logins (HTTP status code 200)
    if auth_status_code == 200 then
        -- Decode the JSON response text
        local resp = json.decode(auth_response:payload())
        local pf = ""  -- Prefix for userdb fields

        -- If a different username was returned, use it
        if dovecot_account and dovecot_account ~= "" then
            add_extra_field("", "user", dovecot_account)
        end

        -- For passdb queries, userdb fields are prefixed
        if dbtype == PASSDB then
            pf = "userdb_"
        end

        -- Process the attributes from the response
        if resp and resp.attributes then
            -- Quota information
            if resp.attributes.rnsMSQuota then
                add_extra_field(pf, "quota_rule=*:bytes", resp.attributes.rnsMSQuota[1])
            end

            -- Quota overrun
            if resp.attributes.rnsMSOverQuota then
                add_extra_field(pf, "quota_over_flag", resp.attributes.rnsMSOverQuota[1])
            end

            -- Mailbox path
            if resp.attributes.rnsMSMailPath then
                add_extra_field(pf, "mail", resp.attributes.rnsMSMailPath[1])
            end

            -- ACL groups
            if resp.attributes["ACL-Groups"] then
                add_extra_field(pf, "acl_groups", resp.attributes["ACL-Groups"][1])
            end
        end

        -- Return successful response
        if dbtype == PASSDB then
            return dovecot.auth.PASSDB_RESULT_OK, extra_fields
        else
            return dovecot.auth.USERDB_RESULT_OK, extra_fields
        end
    end

    -- Handle failed logins (HTTP status code 403)
    if auth_status_code == 403 then
        if dbtype == PASSDB then
            -- Check if the account is disabled
            if auth_status_message == http_access_denied then
                return dovecot.auth.PASSDB_RESULT_USER_DISABLED, auth_status_message
            end

            -- Otherwise, the password is incorrect
            return dovecot.auth.PASSDB_RESULT_PASSWORD_MISMATCH, auth_status_message
        else
            -- For userdb queries, 403 means the user is unknown
            return dovecot.auth.USERDB_RESULT_USER_UNKNOWN, auth_status_message
        end
    end

    -- Handle communication errors with Nauthilus (HTTP status codes 50X)
    if dbtype == PASSDB then
        return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, ""
    else
        return dovecot.auth.USERDB_RESULT_INTERNAL_FAILURE, ""
    end
end

-- Function for userdb lookups (retrieving user information)
-- This function is called by Dovecot to retrieve user information
-- Parameters:
--   request: Dovecot request object
-- Returns:
--   Dovecot authentication result and additional fields
function auth_userdb_lookup(request)
    -- Call query_db with empty password and USERDB type
    return query_db(request, "", USERDB)
end

-- Function for passdb lookups without password verification
-- This function is called by Dovecot when only checking for user existence
-- Parameters:
--   request: Dovecot request object
-- Returns:
--   Dovecot authentication result and additional fields
function auth_passdb_lookup(request)
    -- Call query_db with empty password and USERDB type
    local result, extra_fields = query_db(request, "", USERDB)

    -- Set the nopassword flag to indicate that no password verification should take place
    if type(extra_fields) == "table" then
        extra_fields.nopassword = "y"
    else
        extra_fields = { nopassword = "y" }
    end

    return result, extra_fields
end

-- Function for password verification
-- This function is called by Dovecot to verify a password
-- Parameters:
--   request: Dovecot request object
--   password: The password to verify
-- Returns:
--   Dovecot authentication result and additional fields
function auth_password_verify(request, password)
    -- Call query_db with the password and PASSDB type
    return query_db(request, password, PASSDB)
end

-- Initialization function for the script
-- This function is called by Dovecot when loading the script
-- Returns:
--   0 on success, other values on error
function script_init()
    -- Initialize HTTP authentication
    init_http()

    return 0
end

-- Cleanup function for the script
-- This function is called by Dovecot when unloading the script
function script_deinit()
    -- Cleanup could happen here if needed
end

-- Function to list all user accounts
-- This function is called by Dovecot to retrieve all available user accounts
-- Returns:
--   List of user accounts
function auth_userdb_iterate()
    local user_accounts = {}

    -- Create an HTTP request to the Nauthilus server
    -- with the mode=list-accounts parameter
    local list_request = http_client:request {
        url = http_uri .. "?mode=list-accounts";
        method = "GET";
    }

    -- Add HTTP Basic Authentication
    list_request:add_header("Authorization", "Basic " .. http_basicauthpassword)

    -- Set the Accept header to application/json
    list_request:add_header("Accept", "application/json")

    -- Send the request and process the response
    local list_response = list_request:submit()
    local resp_status = list_response:status()

    -- On successful response, decode the JSON response
    if resp_status == 200 then
        user_accounts = json.decode(list_response:payload())
    end

    return user_accounts
end
```

### Authentication with Keycloak

Here is an example of integrating Nauthilus with Keycloak, based on the [nauthilus-keycloak](https://github.com/croessner/nauthilus-keycloak) project:

#### Overview

Nauthilus can serve as an authentication backend for Keycloak. A special authenticator for Keycloak is used, which forwards authentication requests to Nauthilus. After successful authentication, Nauthilus returns an account name that must correspond to a known user in Keycloak.

The authentication flow is as follows:

1. User opens the Keycloak login page
2. User enters credentials
3. Keycloak forwards the authentication request to Nauthilus
4. Nauthilus verifies the credentials and returns a response
5. On successful authentication, Keycloak continues with the username
6. On failed authentication, Keycloak displays an error message

#### Installation and Configuration

1. Build the Nauthilus authenticator for Keycloak:

```bash
git clone https://github.com/croessner/nauthilus-keycloak.git
cd nauthilus-keycloak
mvn clean package
```

2. Copy the JAR file to your Keycloak environment and restart the service.

3. Configure the authenticator with environment variables or through the Keycloak user interface:

**Option 1: Environment Variables**

```bash
export NAUTHILUS_LOGIN_URL=https://login.example.com/api/v1/auth/json
export NAUTHILUS_PROTOCOL=keycloak
# If Nauthilus requires HTTP Basic Authentication
export NAUTHILUS_USERNAME=username
export NAUTHILUS_PASSWORD=password
```

**Option 2: Keycloak User Interface**

Click on the settings gear next to the Nauthilus step and add your values accordingly.

4. Configure Nauthilus for use with Keycloak:

```yaml
ldap:
  config:
    server_uri: ldap://ldap.example.com:389/
    starttls: true
  search:
    - protocol: keycloak
      cache_name: keycloak
      base_dn: ou=people,dc=example,dc=com
      filter:
        user: |
          (&
            (objectClass=inetOrgPerson)
            (uniqueIdentifier=%L{user})
          )
      mapping:
        account_field: uniqueIdentifier
      attribute:
        - uniqueIdentifier
```

5. Configure the authentication flow in Keycloak:

- Go to "Authentication" > "Flows"
- Copy the "browser" flow
- Replace the "Username Password Form" authenticator with the "Nauthilus authenticator"
- Configure the Nauthilus authenticator with the appropriate settings

#### Notes

- Nauthilus returns an account name that must correspond to a known user in Keycloak
- The LDAP configuration in Nauthilus must match the settings in Keycloak
- Make sure the user federation in Keycloak is configured correctly

## Workshop Exercises

### Exercise 1: Complete Nauthilus Installation

In this exercise, we'll install Nauthilus with Docker Compose and configure it for authentication with a Lua backend.

1. Create a directory for the project:

```bash
mkdir -p nauthilus-workshop
cd nauthilus-workshop
```

2. Create a Docker Compose file:

```yaml
version: '3'

services:
  nauthilus:
    image: ghcr.io/croessner/nauthilus:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/nauthilus
      - ./lua-plugins.d:/etc/nauthilus/lua-plugins.d
    environment:
      - TZ=Europe/Berlin
      - NAUTHILUS_EXPERIMENTAL_ML=true
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

3. Create the configuration files:

```bash
mkdir -p config lua-plugins.d/backend lua-plugins.d/filters lua-plugins.d/features
```

4. Create a configuration file `config/nauthilus.yml`:

```yaml
server:
  address: "0.0.0.0:8080"
  instance_name: "nauthilus-workshop"
  log:
    level: "info"
    format: "json"
  backends:
    - lua

  redis:
    # If Redis runs on 127.0.0.1:6379, no configuration is necessary
    # For other targets, master: and replica: must be configured
    master:
      address: "redis:6379"
    replica:
      addresses:
      - "redis:6379"
```

5. Create a simple Lua backend in `lua-plugins.d/backend/simple.lua`:

```lua
local nauthilus_util = require("nauthilus_util")

-- Hardcoded user list
local users = {
    ["user1"] = {password = "password1", account = "user1@example.com"},
    ["user2"] = {password = "password2", account = "user2@example.com"}
}

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local user = users[request.username]

    if user then
        b:user_found(true)
        b:account_field("account")

        if not request.no_auth then
            b:authenticated(user.password == request.password)
        end

        b:attributes({account = user.account})
    else
        b:user_found(false)
        b:authenticated(false)
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end
```

6. Update your Nauthilus configuration in `config/nauthilus.yml`:

```yaml
   lua:
     config:
       backend_script_path: "/etc/nauthilus/lua-plugins.d/backend/simple.lua"
```
7. Start the services:

```bash
docker compose up -d
```

8. Test the authentication:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

### Exercise 2: Implementing an IP Filter

In this exercise, we'll implement a filter that blocks requests from specific IP addresses.

1. Create a file `lua-plugins.d/filters/ip_blocklist.lua`:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- List of blocked IP addresses
    local blocked_ips = {
        "192.168.1.100",
        "10.0.0.50"
    }

    -- Check if the client IP is in the blocklist
    for _, ip in ipairs(blocked_ips) do
        if request.client_ip == ip then
            nauthilus_builtin.custom_log_add("blocked_ip", request.client_ip)
            nauthilus_builtin.status_message_set("IP address blocked")

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- The request should be accepted
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
```

2. Update your Nauthilus configuration in `config/nauthilus.yml`:

```yaml
lua:
  filters:
    - name: "ip_blocklist"
      script_path: "/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua"
```

3. Restart Nauthilus:

```bash
docker compose restart nauthilus
```

4. Test the filter:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"192.168.1.100","service":"http"}' http://localhost:8080/api/v1/auth/json
```

### Exercise 3: Implementing a Logging Feature

In this exercise, we'll implement a feature that logs authentication attempts.

1. Create a file `lua-plugins.d/features/logging.lua`:

```lua
function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Log the authentication attempt
    nauthilus_builtin.custom_log_add("auth_attempt_username", request.username)
    nauthilus_builtin.custom_log_add("auth_attempt_ip", request.client_ip)
    nauthilus_builtin.custom_log_add("auth_attempt_protocol", request.protocol)

    if request.user_agent then
        nauthilus_builtin.custom_log_add("auth_attempt_user_agent", request.user_agent)
    end

    -- Trigger feature but continue processing
    return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
```

2. Update your Nauthilus configuration in `config/nauthilus.yml`:

```yaml
lua:
  features:
    - name: "logging"
      script_path: "/etc/nauthilus/lua-plugins.d/features/logging.lua"
  filters:
    - name: "ip_blocklist"
      script_path: "/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua"
```

3. Restart Nauthilus:

```bash
docker compose restart nauthilus
```

4. Test the feature:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Summary

In this workshop, we covered the following topics:

1. **Introduction to Nauthilus**: We learned about the architecture and main features of Nauthilus.
2. **Installation and Setup**: We learned about different methods for installing and configuring Nauthilus.
3. **Lua Backends**: We learned how to implement custom authentication backends in Lua.
4. **Lua Filters**: We learned how to implement filters to validate authentication requests.
5. **Lua Features**: We learned how to implement features to provide additional functionality.
6. **Monitoring and Debugging**: We learned about various options for monitoring and debugging Nauthilus.
7. **Advanced Topics**: We covered advanced topics such as load balancing, security, and performance optimization.
8. **Example Applications**: We saw how Nauthilus can be used in different scenarios.
9. **Practical Exercises**: We performed practical exercises to apply what we learned.

Nauthilus is a powerful and flexible authentication and authorization platform that can be adapted to various use cases. By using Lua scripts, you can extend and customize the behavior of Nauthilus to meet your specific requirements.

## Further Resources

- **Official Website**: [https://nauthilus.org](https://nauthilus.org)
- **GitHub Repository**: [https://github.com/croessner/nauthilus](https://github.com/croessner/nauthilus)
- **Documentation**: [https://nauthilus.org/docs/intro](https://nauthilus.org/docs/intro)
- **Mailing Lists**: [https://lists.nauthilus.org](https://lists.nauthilus.org)

## Appendix

### Useful Lua Functions

#### nauthilus_util

- `exists_in_table(tbl, element)`: Checks if an element exists in a table
- `get_current_timestamp()`: Returns a timestamp
- `table_length(tbl)`: Calculates the length of a table
- `if_error_raise(err)`: Raises an error if an error has occurred
- `is_table(object)`: Checks if an object is a table
- `is_string(object)`: Checks if an object is a string
- `is_number(object)`: Checks if an object is a number
- `toboolean(str)`: Converts a string to a boolean value
- `generate_random_string(length)`: Generates a random string
- `is_routable_ip(ip)`: Checks if an IP address is routable
- `print_result(logging, result, err_string)`: Outputs a result

#### nauthilus_builtin

- `custom_log_add(key, value)`: Adds a custom log entry
- `status_message_set(message)`: Sets a status message

#### nauthilus_context

- `context_get(key)`: Gets a value from the context
- `context_set(key, value)`: Sets a value in the context

#### nauthilus_prometheus

- `increment_counter(name, labels)`: Increments a counter
- `increment_gauge(name, labels)`: Increments a gauge
- `decrement_gauge(name, labels)`: Decrements a gauge
- `start_histogram_timer(name, labels)`: Starts a timer for a histogram
- `stop_timer(timer)`: Stops a timer

### Example: Complete Nauthilus Configuration

```yaml
server:
  address: "0.0.0.0:8080"
  haproxy_v2: false
  max_concurrent_requests: 1000
  max_password_history_entries: 50

  basic_auth:
    enabled: true
    username: authserv
    password: authserv

  instance_name: "nauthilus"

  log:
    json: true
    color: false
    level: info
    debug_modules:
      - auth
      - lua

  backends: [ cache, ldap  ]
  features: [ brute_force, tls_encryption, rbl, relay_domains, lua ]
  brute_force_protocols: [ imap, imaps, submission, smtp, smtps ]

  dns:
    resolver: 10.0.118.1
    timeout: 3
    resolve_client_ip: false

  insights:
    enable_pprof: true
    enable_block_profile: true

  tls:
    enabled: true
    cert: "/etc/nauthilus/cert.pem"
    key: "/etc/nauthilus/key.pem"
    http_client_skip_verify: true

  prometheus_timer:
    enabled: true
    labels: [ backend, filter, action, post_action, request, feature, brute_force, dns ]
    
  master_user:
    enabled: true
    delimiter: "*"

  redis:
    # If Redis runs on 127.0.0.1:6379, no configuration is necessary
    # For other targets, master: and replica: must be configured
    master:
      address: "127.0.0.1:6379"
   
    replica:
      addresses:
        - "127.0.0.1:6379"
   
    database_number: 0
    prefix: nt_
    pool_size: 10
    idle_pool_size: 5
    positive_cache_ttl: 3600
    negative_cache_ttl: 7200

realtime_blackhole_lists:
  threshold: 10

  lists:
    - name: SpamRats AuthBL
      rbl: auth.spamrats.com
      ipv4: true
      ipv6: true
      return_code: 127.0.0.43
      weight: 10
      allow_failure: true

  ip_whitelist:
    - 127.0.0.0/8
    - ::1
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - fd00::/8
    - 169.254.0.0/16
    - fe80::/10

ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 4
    lookup_idle_pool_size: 1
    auth_pool_size: 4
    auth_idle_pool_size: 2
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: true
    bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
    bind_pw: "secret"

  search:
    - protocol: [ default, http ]
      cache_name: http
      base_dn: "ou=people,ou=it,dc=example,dc=com"
      filter:
        user: |
          (|
            (uniqueIdentifier=%L{user})
            (mail=%L{user})
          )
      mapping:
        account_field: mail
      attribute: mail

brute_force:
  ip_whitelist:
    - 127.0.0.0/8
    - ::1
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - fd00::/8
    - 169.254.0.0/16
    - fe80::/10

  neural_network:
    max_training_records: 30000
    hidden_neurons: 20
    activation_function: relu

  buckets:
    - { name: b_1m_ipv4_32,  period: 1m,   cidr: 32, ipv4: true, failed_requests: 10 }
    - { name: b_1h_ipv4_24,  period: 1h,   cidr: 24, ipv4: true, failed_requests: 15 }
    - { name: b_1d_ipv4_24,  period: 24h,  cidr: 24, ipv4: true, failed_requests: 25 }
    - { name: b_1w_ipv4_24,  period: 168h, cidr: 24, ipv4: true, failed_requests: 40 }

    - { name: b_1m_ipv6_128, period: 1m,   cidr: 128, ipv6: true, failed_requests: 10 }
    - { name: b_1h_ipv6_64,  period: 1h,   cidr: 64,  ipv6: true, failed_requests: 15 }
    - { name: b_1d_ipv6_64,  period: 24h,  cidr: 64,  ipv6: true, failed_requests: 25 }
    - { name: b_1w_ipv6_64,  period: 168h, cidr: 64,  ipv6: true, failed_requests: 40 }

lua:
  features:
    - name: "blocklist"
      script_path: "/etc/nauthilus/lua-plugins.d/features/blocklist.lua"
    - name: "neural"
      script_path: "/etc/nauthilus/lua-plugins.d/features/neural.lua"

  filters:
    - name: "geoip"
      script_path: "/etc/nauthilus/lua-plugins.d/filters/geoip.lua"

  config:
    package_path: "/etc/nauthilus/lua/lib/?.lua"
```

This comprehensive workshop document provides you with all the information you need to understand, install, configure, and extend Nauthilus. We hope you enjoy this workshop and can use Nauthilus for your authentication and authorization requirements.
