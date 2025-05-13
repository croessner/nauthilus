# JWT Authentication

Nauthilus now supports JWT (JSON Web Token) authentication as an alternative to HTTP Basic Authentication. This document explains how to configure and use JWT authentication.

## Configuration

To enable JWT authentication, add the following configuration to your Nauthilus configuration file:

```yaml
server:
  jwt_auth:
    enabled: true
    secret_key: "your-secret-key-at-least-32-characters-long"
    token_expiry: 1h
    refresh_token: true
    store_in_redis: true  # For multi-instance compatibility
    users:                # Optional: Define JWT-specific users
      - username: "admin"
        password: "admin-password"
        roles: ["authenticated", "user_info", "list_accounts"]
      - username: "user"
        password: "user-password"
        roles: ["authenticated"]
```

Configuration options:

- `enabled`: Set to `true` to enable JWT authentication.
- `secret_key`: A secret key used to sign JWT tokens. Should be at least 32 characters long.
- `token_expiry`: The expiry time for JWT tokens. Accepts time duration format (e.g., "1h", "30m", "24h").
- `refresh_token`: Set to `true` to enable refresh tokens.
- `store_in_redis`: Set to `true` to store tokens in Redis for multi-instance compatibility.
- `users`: Optional list of JWT-specific users with their roles.
  - `username`: The username for the JWT user.
  - `password`: The password for the JWT user.
  - `roles`: List of roles assigned to the user. Default roles include:
    - `authenticated`: Basic access role.
    - `user_info`: Access to user information.
    - `list_accounts`: Access to list accounts.

    You can also define custom roles for your users and use them for custom hooks or other role-based access control mechanisms.

You also need to ensure that the JWT endpoint is not disabled:

```yaml
server:
  disabled_endpoints:
    auth_jwt: false
```

## Endpoints

JWT authentication provides the following endpoints:

### Token Generation

```
POST /api/v1/jwt/token
```

Request body:
```json
{
  "username": "your-username",
  "password": "your-password"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": 1620000000
}
```

### Token Refresh

```
POST /api/v1/jwt/refresh
```

Headers:
```
X-Refresh-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": 1620000000
}
```

### Protected Endpoints

All endpoints under `/api/v1` are protected and require a valid JWT token in the Authorization header, except for the token generation and refresh endpoints:

```
GET /api/v1/:category/:service
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

The following endpoints are public and do not require authentication:
- `/api/v1/jwt/token` - For generating tokens
- `/api/v1/jwt/refresh` - For refreshing tokens

## Role-Based Access Control

JWT tokens include roles that determine what actions the user can perform:

- `authenticated`: All authenticated users have this role.
- `user_info`: Users with NoAuth=true have this role. This role is required to access endpoints with `mode=no-auth`.
- `list_accounts`: Users who can list accounts have this role. This role is required to access endpoints with `mode=list-accounts`.
- Custom roles: You can define custom roles for your users and use them for custom hooks.

The roles are enforced in the authentication process. If a user attempts to access an endpoint that requires a specific role, and the user doesn't have that role, the request will be rejected with an appropriate error message. This ensures that users can only perform actions that they are authorized to do.

### Role-Based Access Control for Custom Hooks

You can configure roles for custom hooks to restrict access to specific users. When JWT authentication is enabled, the roles specified for a hook are checked against the roles in the user's JWT token. If the user doesn't have any of the required roles, the request is rejected with a 403 Forbidden status.

To configure roles for a custom hook, add a `roles` field to the hook configuration:

```yaml
lua:
  custom_hooks:
    - http_location: "status"
      http_method: "GET"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/status_check.lua"
      roles: ["admin", "monitoring"]
    - http_location: "user-info"
      http_method: "GET"
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/user_info.lua"
      roles: ["user_info"]
```

In this example:
- The "status" hook requires the user to have either the "admin" or "monitoring" role.
- The "user-info" hook requires the user to have the "user_info" role.

If no roles are specified for a hook, any authenticated user can access it when JWT is enabled.

## Using JWT Authentication

### With curl

Generate a token:
```bash
curl -X POST http://localhost:8080/api/v1/jwt/token \
  -H "Content-Type: application/json" \
  -d '{"username":"your-username","password":"your-password"}'
```

Access a protected endpoint:
```bash
curl -X GET http://localhost:8080/api/v1/protected/auth/basic \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Refresh a token:
```bash
curl -X POST http://localhost:8080/api/v1/jwt/refresh \
  -H "X-Refresh-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### With JavaScript

```javascript
// Generate a token
async function getToken(username, password) {
  const response = await fetch('http://localhost:8080/api/v1/jwt/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });
  return response.json();
}

// Access a protected endpoint
async function getProtectedResource(token) {
  const response = await fetch('http://localhost:8080/api/v1/protected/auth/basic', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  return response.json();
}

// Refresh a token
async function refreshToken(refreshToken) {
  const response = await fetch('http://localhost:8080/api/v1/jwt/refresh', {
    method: 'POST',
    headers: {
      'X-Refresh-Token': refreshToken,
    },
  });
  return response.json();
}
```

## Authentication Flow

The JWT authentication flow works as follows:

1. **Token Generation**:
   - The client sends a request to `/api/v1/jwt/token` with username and password.
   - Nauthilus validates the credentials against either:
     - The configured JWT users in the configuration file, or
     - The existing authentication backends (LDAP, SQL, etc.) if no JWT users are configured.
   - If authentication is successful, Nauthilus generates a JWT token and (optionally) a refresh token.
   - If `store_in_redis` is enabled, the tokens are stored in Redis for multi-instance compatibility.
   - The tokens are returned to the client.

2. **Using the Token**:
   - The client includes the JWT token in the Authorization header of subsequent requests.
   - Nauthilus validates the token by:
     - Verifying the token signature.
     - Checking that the token has not expired.
     - If `store_in_redis` is enabled, verifying that the token exists in Redis.
   - If the token is valid, the request is processed.

3. **Token Refresh**:
   - When the token is about to expire, the client can request a new token using the refresh token.
   - The client sends a request to `/api/v1/jwt/refresh` with the refresh token.
   - Nauthilus validates the refresh token and generates a new JWT token and refresh token.
   - The new tokens are returned to the client.

## Multi-Instance Compatibility

When running Nauthilus in a multi-instance environment (e.g., behind a load balancer), you need to enable Redis storage for JWT tokens to ensure that tokens generated by one instance can be validated by another instance.

To enable Redis storage for JWT tokens, set `store_in_redis: true` in the JWT configuration:

```yaml
server:
  jwt_auth:
    enabled: true
    secret_key: "your-secret-key-at-least-32-characters-long"
    token_expiry: 1h
    refresh_token: true
    store_in_redis: true
```

When Redis storage is enabled:
- Tokens are stored in Redis with an expiry time matching the token's expiry time.
- Token validation checks Redis to ensure the token exists and matches the one provided by the client.
- This ensures that tokens can be validated across multiple instances of Nauthilus.

## Security Considerations

- Keep your secret key secure and never expose it.
- Use HTTPS for all API requests to prevent token interception.
- Set an appropriate token expiry time based on your security requirements.
- Consider implementing token revocation if needed for your use case.
- When using JWT users, ensure passwords are strong and changed regularly.
- In production environments, enable Redis storage for tokens to prevent token reuse after logout.
