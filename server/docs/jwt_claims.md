# JWT Claims Formats in Nauthilus

## Overview

This document explains the various JWT claim formats supported by the `HasRole` function in the `jwtutil` package. The function is designed to be flexible and handle different claim formats to ensure compatibility across various parts of the application and with external JWT providers.

## Why Multiple Claim Formats?

The `HasRole` function supports multiple claim formats for several reasons:

1. **Compatibility**: Different parts of the application or external systems might generate JWT tokens with varying structures.
2. **Testing**: Test cases need to simulate different claim formats to ensure the function works correctly in all scenarios.
3. **Evolution**: As the application evolves, the claim format might change, but backward compatibility is maintained.
4. **Integration**: When integrating with third-party systems, we need to handle their JWT formats.

## Supported Claim Formats

The `HasRole` function in `jwtutil/claims.go` handles the following claim formats:

### 1. ClaimsWithRoles Interface

Any type that implements the `jwtclaims.ClaimsWithRoles` interface can be used. This interface requires a `HasRole(role string) bool` method.

```
// ClaimsWithRoles is an interface for any type that can check if it has a specific role
type ClaimsWithRoles interface {
    HasRole(role string) bool
}
```

This is the most flexible approach as it allows any type to define its own logic for role checking.

### 2. JWTClaims Struct

The `jwtclaims.JWTClaims` struct is the standard claim format used by the application:

```
type JWTClaims struct {
    Username string   `json:"username"`
    Roles    []string `json:"roles,omitempty"`
    jwt.RegisteredClaims
}
```

This struct implements the `ClaimsWithRoles` interface and is the preferred format for new code.

### 3. Local Struct with Roles

A simple struct with Username and Roles fields:

```
type localClaimsWithRoles struct {
    Username string
    Roles    []string
}
```

This format is used for backward compatibility and simpler implementations.

### 4. Anonymous Struct (Used in Tests)

An anonymous struct with JSON tags, commonly used in tests:

```
struct {
    Username string   `json:"username"`
    Roles    []string `json:"roles,omitempty"`
}
```

### 5. Map[string]interface{} with Roles

A generic map representation of claims, which is common when parsing JWT tokens:

```
map[string]interface{}{
    "username": "user",
    "roles": []string{"role1", "role2"}
}
```

The function handles two variations of the roles field in maps:
- `roles` as `[]string`
- `roles` as `[]interface{}` (which is common when deserializing JSON)

## Implementation Details

The `HasRole` function uses type assertions to check each possible format in a specific order:

1. First, it checks if the claims implement the `ClaimsWithRoles` interface
2. Then, it checks if the claims are a pointer to `jwtclaims.JWTClaims`
3. Next, it tries to match with a local struct that has Roles field
4. It also checks for the anonymous struct format used in tests
5. Finally, it handles the map[string]interface{} format with different role array types

This approach allows the function to work with various claim formats without using reflection, which improves performance.

## Best Practices

When working with JWT claims in Nauthilus:

1. Use the `jwtclaims.JWTClaims` struct for new code
2. Implement the `ClaimsWithRoles` interface for custom claim types
3. Be aware that the `HasRole` function can handle various formats, but the preferred format is `jwtclaims.JWTClaims`

## Conclusion

The multiple claim formats supported by the `HasRole` function provide flexibility and compatibility across different parts of the application and with external systems. This design choice ensures that the function can handle various JWT token formats while maintaining good performance by avoiding reflection.
