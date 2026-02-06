# CSRF Middleware API Documentation

This document provides comprehensive API documentation for the Nauthilus CSRF (Cross-Site Request Forgery) middleware
package located at `server/middleware/csrf`.

## Overview

The CSRF middleware provides protection against Cross-Site Request Forgery attacks using the **Double-Submit Cookie
Pattern** with **One-Time-Pad Token Masking** to prevent BREACH attacks. It is designed as an object-oriented,
interface-based replacement for external dependencies like `nosurf` and `gin-adapter`.

### Key Features

- **Double-Submit Cookie Pattern**: Stores a token in both a cookie and expects it in requests
- **One-Time-Pad Masking**: Each token response is uniquely masked to prevent BREACH compression attacks
- **Origin/Referer Validation**: Validates request origin to prevent cross-origin attacks
- **Sec-Fetch-Site Support**: Modern browser header support for same-origin validation
- **Constant-Time Comparison**: Secure token validation using `crypto/subtle`
- **Functional Options Pattern**: Flexible configuration through option functions
- **Full Interface-Based Design**: All components are replaceable via interfaces

---

## Quick Start

### Basic Usage

```go
import "github.com/croessner/nauthilus/server/middleware/csrf"

// Simple middleware setup
router.Use(csrf.New())

// Get token in handler for form/template
func myHandler(ctx *gin.Context) {
token := csrf.Token(ctx)
ctx.HTML(http.StatusOK, "form.html", gin.H{
"CSRFToken": token,
})
}
```

### HTML Form Integration

```html

<form method="POST" action="/submit">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <!-- other form fields -->
    <button type="submit">Submit</button>
</form>
```

### AJAX/Fetch Integration

```javascript
// Get token from meta tag or hidden input
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify(data)
});
```

---

## Package Constants

| Constant        | Value            | Description                                  |
|-----------------|------------------|----------------------------------------------|
| `CookieName`    | `"_csrf"`        | Default name for the CSRF cookie             |
| `FormFieldName` | `"csrf_token"`   | Default form field name for token submission |
| `HeaderName`    | `"X-CSRF-Token"` | HTTP header name for token submission        |
| `tokenLength`   | `32`             | Raw token length in bytes                    |

---

## Interfaces

### Handler Interface

The main interface for CSRF handlers.

```go
type Handler interface {
// Middleware returns the Gin middleware function
Middleware() gin.HandlerFunc

// Token returns the masked CSRF token for the current request
Token(ctx *gin.Context) string

// RegenerateToken generates and returns a new CSRF token
RegenerateToken(ctx *gin.Context) string

// SetFailureHandler sets the handler called when CSRF validation fails
SetFailureHandler(handler gin.HandlerFunc)

// SetBaseCookie sets the base cookie configuration
SetBaseCookie(cookie http.Cookie)

// Reason returns the error that caused CSRF validation to fail
Reason(ctx *gin.Context) error
}
```

### TokenGenerator Interface

Interface for generating random CSRF tokens.

```go
type TokenGenerator interface {
// Generate creates a new random CSRF token (32 bytes)
Generate() ([]byte, error)
}
```

### TokenMasker Interface

Interface for one-time-pad masking operations.

```go
type TokenMasker interface {
// Mask applies one-time-pad masking to a token
// Returns 64 bytes: 32-byte key + 32-byte masked token
Mask(token []byte) ([]byte, error)

// Unmask removes the one-time-pad masking from a token
// Expects 64 bytes, returns original 32-byte token
Unmask(maskedToken []byte) []byte
}
```

### TokenValidator Interface

Interface for validating CSRF tokens.

```go
type TokenValidator interface {
// Validate checks if the sent token matches the real token
// realToken: 32 bytes (unmasked), sentToken: 64 bytes (masked)
Validate(realToken, sentToken []byte) bool
}
```

### TokenEncoder Interface

Interface for encoding tokens to strings.

```go
type TokenEncoder interface {
// Encode converts bytes to a string representation
Encode(data []byte) string

// Decode converts a string representation back to bytes
Decode(data string) ([]byte, error)
}
```

### OriginValidator Interface

Interface for validating request origin.

```go
type OriginValidator interface {
// ValidateOrigin checks if the request origin is allowed
ValidateOrigin(r *http.Request, selfOrigin *url.URL) error
}
```

---

## Types

### DefaultHandler

The main CSRF handler implementation.

```go
type DefaultHandler struct {
failureHandler  gin.HandlerFunc
baseCookie      http.Cookie
generator       TokenGenerator
masker          TokenMasker
validator       TokenValidator
encoder         TokenEncoder
originValidator OriginValidator
}
```

#### Constructor

```go
func NewHandler(opts ...Option) *DefaultHandler
```

Creates a new CSRF handler with optional configuration. Default values:

- Cookie: `Name="_csrf"`, `Path="/"`, `HttpOnly=true`, `Secure=false`, `SameSite=StrictMode`
- Failure handler: Returns `403 Forbidden`
- Uses default implementations for all interfaces

### DefaultOriginValidator

Validates Origin and Referer headers.

```go
type DefaultOriginValidator struct {
allowedOrigins map[string]bool
}
```

#### Constructor

```go
func NewOriginValidator(allowedOrigins ...string) *DefaultOriginValidator
```

Creates an origin validator with optional additional allowed origins.

---

## Configuration Options

All options follow the functional options pattern.

### WithFailureHandler

```go
func WithFailureHandler(handler gin.HandlerFunc) Option
```

Sets a custom handler for CSRF validation failures.

**Example:**

```go
handler := csrf.NewHandler(
csrf.WithFailureHandler(func(ctx *gin.Context) {
ctx.JSON(http.StatusForbidden, gin.H{
"error": "CSRF validation failed",
"reason": csrf.Token(ctx),
})
}),
)
```

### WithBaseCookie

```go
func WithBaseCookie(cookie http.Cookie) Option
```

Sets the base cookie configuration for CSRF tokens.

**Example:**

```go
handler := csrf.NewHandler(
csrf.WithBaseCookie(http.Cookie{
Name:     "my_csrf_token",
Path:     "/",
Secure:   true,
HttpOnly: true,
SameSite: http.SameSiteStrictMode,
MaxAge:   3600,
}),
)
```

### WithGenerator

```go
func WithGenerator(generator TokenGenerator) Option
```

Sets a custom token generator implementation.

### WithMasker

```go
func WithMasker(masker TokenMasker) Option
```

Sets a custom token masker implementation.

### WithValidator

```go
func WithValidator(validator TokenValidator) Option
```

Sets a custom token validator implementation.

### WithEncoder

```go
func WithEncoder(encoder TokenEncoder) Option
```

Sets a custom token encoder implementation.

### WithOriginValidator

```go
func WithOriginValidator(validator OriginValidator) Option
```

Sets a custom origin validator implementation.

---

## Package Functions

### New

```go
func New() gin.HandlerFunc
```

Creates and returns a CSRF middleware with default settings. This is the simplest way to add CSRF protection.

**Example:**

```go
router.Use(csrf.New())
```

### Token

```go
func Token(ctx *gin.Context) string
```

Returns the masked CSRF token for the current request context. This is a convenience function that retrieves the token
from the context.

**Example:**

```go
func handler(ctx *gin.Context) {
token := csrf.Token(ctx)
ctx.HTML(http.StatusOK, "form.html", gin.H{
"CSRFToken": token,
})
}
```

### GetToken

```go
func GetToken(ctx *gin.Context) string
```

Alias for `Token()`. Returns the masked CSRF token.

---

## Error Types

The package defines the following error types for CSRF validation failures:

| Error                   | Description                                              |
|-------------------------|----------------------------------------------------------|
| `ErrNoReferer`          | Secure request has no Referer header or it was malformed |
| `ErrBadReferer`         | Referer header specifies a different origin              |
| `ErrBadOrigin`          | Origin header specifies a disallowed origin              |
| `ErrBadToken`           | Token in cookie doesn't match token in form/header       |
| `ErrNoToken`            | No CSRF token found in the request                       |
| `ErrInvalidTokenLength` | Token has an invalid length                              |

### Accessing the Failure Reason

```go
func handler(ctx *gin.Context) {
h := csrf.NewHandler()
reason := h.Reason(ctx)
if reason != nil {
log.Printf("CSRF failed: %v", reason)
}
}
```

---

## How It Works

### Token Flow

1. **GET Request**: Middleware generates a 32-byte random token, stores it in an `HttpOnly` cookie, and makes a masked (
   64-byte) version available via `Token(ctx)`.

2. **POST/PUT/DELETE Request**: Client must include the masked token either in:
    - Form field: `csrf_token`
    - HTTP header: `X-CSRF-Token`

3. **Validation**: Middleware:
    - Reads the raw token from the cookie
    - Reads the masked token from form/header
    - Unmasks the submitted token using XOR
    - Compares tokens using constant-time comparison

### One-Time-Pad Masking

To prevent BREACH attacks (where compression reveals token bytes), each token response is uniquely masked:

```
Masked Token (64 bytes) = Random Key (32 bytes) || XOR(Token, Key) (32 bytes)
```

Unmasking:

```
Original Token = XOR(Masked[32:64], Masked[0:32])
```

### Origin Validation

Before token validation, the middleware checks:

1. **Sec-Fetch-Site Header** (modern browsers): If present and equals `same-origin`, validation passes
2. **Origin Header**: Must match the request's host
3. **Referer Header** (fallback): Used when Origin is not present; must match request origin

### Safe Methods

The following HTTP methods are considered "safe" and skip token validation:

- `GET`
- `HEAD`
- `OPTIONS`
- `TRACE`

---

## Default Implementations

### DefaultTokenGenerator

Uses `crypto/rand` to generate cryptographically secure 32-byte tokens.

```go
generator := csrf.NewTokenGenerator()
token, err := generator.Generate()
```

### DefaultTokenMasker

Implements XOR-based one-time-pad masking.

```go
masker := csrf.NewTokenMasker()
masked, err := masker.Mask(token) // 32 bytes → 64 bytes
unmasked := masker.Unmask(masked) // 64 bytes → 32 bytes
```

### DefaultTokenValidator

Validates tokens using constant-time comparison.

```go
validator := csrf.NewTokenValidator()
valid := validator.Validate(realToken, sentToken)
```

### Base64Encoder

Uses URL-safe Base64 encoding (no `+` or `/` characters).

```go
encoder := csrf.NewTokenEncoder()
encoded := encoder.Encode(token)
decoded, err := encoder.Decode(encoded)
```

---

## Advanced Usage

### Custom Handler with All Options

```go
handler := csrf.NewHandler(
csrf.WithBaseCookie(http.Cookie{
Name:     "app_csrf",
Path:     "/",
Secure:   true,
HttpOnly: true,
SameSite: http.SameSiteStrictMode,
MaxAge:   86400,
}),
csrf.WithFailureHandler(func (ctx *gin.Context) {
ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
"error":   "csrf_failed",
"message": "Invalid or missing CSRF token",
})
}),
csrf.WithOriginValidator(csrf.NewOriginValidator(
"https://trusted-origin.com",
"https://another-trusted.com",
)),
)

router.Use(handler.Middleware())
```

### Regenerating Tokens

For sensitive operations, you may want to regenerate the token:

```go
func sensitiveHandler(ctx *gin.Context) {
h := ctx.MustGet("csrf_handler").(*csrf.DefaultHandler)
newToken := h.RegenerateToken(ctx)

// Use newToken for the next request
}
```

### Per-Route CSRF Protection

```go
csrfMiddleware := csrf.New()

// Apply only to specific routes
router.POST("/api/sensitive", csrfMiddleware, sensitiveHandler)

// Or to a group
apiGroup := router.Group("/api")
apiGroup.Use(csrfMiddleware)
{
apiGroup.POST("/create", createHandler)
apiGroup.PUT("/update", updateHandler)
}
```

---

## Security Considerations

1. **Always use HTTPS in production**: Set `Secure: true` on the cookie
2. **Use SameSite=Strict**: Prevents cookies from being sent with cross-site requests
3. **HttpOnly cookies**: Prevents JavaScript access to the CSRF cookie
4. **Token length**: 32 bytes provides 256 bits of entropy
5. **Constant-time comparison**: Prevents timing attacks
6. **One-time-pad masking**: Prevents BREACH attacks

---

## Testing

The package includes comprehensive unit tests:

- `token_test.go`: Tests for token generation, masking, validation, and encoding
- `csrf_test.go`: Tests for middleware functionality, origin validation, and cookie handling

Run tests:

```bash
go test -v ./server/middleware/csrf/...
```

---

## Migration from nosurf

If migrating from `github.com/justinas/nosurf`:

| nosurf                | This Package          |
|-----------------------|-----------------------|
| `nosurf.New(handler)` | `csrf.New()`          |
| `nosurf.Token(r)`     | `csrf.Token(ctx)`     |
| `nosurf.NewPure()`    | `csrf.NewHandler()`   |
| `nosurf.Reason(r)`    | `handler.Reason(ctx)` |

**Before:**

```go
import (
"github.com/justinas/nosurf"
"github.com/gwatts/gin-adapter"
)

router.Use(adapter.Wrap(nosurf.NewPure))
token := nosurf.Token(ctx.Request)
```

**After:**

```go
import "github.com/croessner/nauthilus/server/middleware/csrf"

router.Use(csrf.New())
token := csrf.Token(ctx)
```

---

## License

Copyright (C) 2024 Christian Rößner

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
