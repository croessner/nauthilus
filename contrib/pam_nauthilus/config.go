package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultScope is the default OIDC scope for the device flow.
	defaultScope = "openid"
	// defaultTimeout is the overall authentication timeout.
	defaultTimeout = 5 * time.Minute
	// defaultRequestTimeout is the timeout for single HTTP requests.
	defaultRequestTimeout = 10 * time.Second
	// defaultUserClaim is the default claim used to match the PAM username.
	defaultUserClaim = "preferred_username"
)

// Settings describes the PAM module configuration options.
type Settings struct {
	Issuer                string
	DeviceEndpoint        string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSEndpoint          string
	IntrospectionEndpoint string
	ClientID              string
	ClientSecret          string
	Scope                 string
	Timeout               time.Duration
	RequestTimeout        time.Duration
	UserClaim             string
	AllowHTTP             bool
	CAFile                string
	TLSServerName         string
}

// EndpointSet contains resolved IdP endpoints used by the module.
type EndpointSet struct {
	Device        string
	Token         string
	UserInfo      string
	JWKS          string
	Introspection string
}

// parseArgs parses PAM arguments into Settings with defaults and validation.
func parseArgs(args []string) (Settings, error) {
	settings := Settings{
		Scope:          defaultScope,
		Timeout:        defaultTimeout,
		RequestTimeout: defaultRequestTimeout,
		UserClaim:      defaultUserClaim,
	}

	for _, raw := range args {
		if raw == "" {
			continue
		}

		key, value, hasValue := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		if !hasValue {
			value = "true"
		} else {
			value = strings.TrimSpace(value)
		}

		switch strings.ToLower(key) {
		case "issuer":
			settings.Issuer = value
		case "device_endpoint":
			settings.DeviceEndpoint = value
		case "token_endpoint":
			settings.TokenEndpoint = value
		case "userinfo_endpoint":
			settings.UserInfoEndpoint = value
		case "jwks_endpoint":
			settings.JWKSEndpoint = value
		case "introspection_endpoint":
			settings.IntrospectionEndpoint = value
		case "client_id":
			settings.ClientID = value
		case "client_secret":
			settings.ClientSecret = value
		case "scope":
			settings.Scope = value
		case "timeout":
			dur, err := parseDurationArg(value)
			if err != nil {
				return Settings{}, fmt.Errorf("invalid timeout: %w", err)
			}

			settings.Timeout = dur
		case "request_timeout":
			dur, err := parseDurationArg(value)
			if err != nil {
				return Settings{}, fmt.Errorf("invalid request_timeout: %w", err)
			}

			settings.RequestTimeout = dur
		case "user_claim":
			settings.UserClaim = value
		case "allow_http":
			allow, err := strconv.ParseBool(value)
			if err != nil {
				return Settings{}, fmt.Errorf("invalid allow_http: %w", err)
			}

			settings.AllowHTTP = allow
		case "ca_file":
			settings.CAFile = value
		case "tls_server_name":
			settings.TLSServerName = value
		default:
			return Settings{}, fmt.Errorf("unknown option: %s", key)
		}
	}

	if err := settings.validate(); err != nil {
		return Settings{}, err
	}

	return settings, nil
}

// Endpoints resolves the effective device, token, and userinfo endpoints.
func (s Settings) Endpoints() (EndpointSet, error) {
	device := s.DeviceEndpoint
	token := s.TokenEndpoint
	userInfo := s.UserInfoEndpoint

	jwks := s.JWKSEndpoint
	introspection := s.IntrospectionEndpoint

	if device == "" || token == "" || userInfo == "" || jwks == "" || introspection == "" {
		issuerURL, err := parseEndpointURL(s.Issuer)
		if err != nil {
			return EndpointSet{}, err
		}

		if device == "" {
			device, err = joinEndpoint(issuerURL, "/oidc/device")
			if err != nil {
				return EndpointSet{}, err
			}
		}

		if token == "" {
			token, err = joinEndpoint(issuerURL, "/oidc/token")
			if err != nil {
				return EndpointSet{}, err
			}
		}

		if userInfo == "" {
			userInfo, err = joinEndpoint(issuerURL, "/oidc/userinfo")
			if err != nil {
				return EndpointSet{}, err
			}
		}

		if jwks == "" {
			jwks, err = joinEndpoint(issuerURL, "/oidc/jwks")
			if err != nil {
				return EndpointSet{}, err
			}
		}

		if introspection == "" {
			introspection, err = joinEndpoint(issuerURL, "/oidc/introspect")
			if err != nil {
				return EndpointSet{}, err
			}
		}
	}

	if err := validateEndpoint(device, s.AllowHTTP); err != nil {
		return EndpointSet{}, fmt.Errorf("invalid device endpoint: %w", err)
	}

	if err := validateEndpoint(token, s.AllowHTTP); err != nil {
		return EndpointSet{}, fmt.Errorf("invalid token endpoint: %w", err)
	}

	if err := validateEndpoint(userInfo, s.AllowHTTP); err != nil {
		return EndpointSet{}, fmt.Errorf("invalid userinfo endpoint: %w", err)
	}

	if err := validateEndpoint(jwks, s.AllowHTTP); err != nil {
		return EndpointSet{}, fmt.Errorf("invalid jwks endpoint: %w", err)
	}

	if err := validateEndpoint(introspection, s.AllowHTTP); err != nil {
		return EndpointSet{}, fmt.Errorf("invalid introspection endpoint: %w", err)
	}

	return EndpointSet{
		Device:        device,
		Token:         token,
		UserInfo:      userInfo,
		JWKS:          jwks,
		Introspection: introspection,
	}, nil
}

// validate enforces required fields and endpoint constraints.
func (s Settings) validate() error {
	if s.ClientID == "" {
		return errors.New("client_id is required")
	}

	if s.ClientSecret == "" {
		return errors.New("client_secret is required")
	}

	if s.Scope == "" {
		return errors.New("scope must not be empty")
	}

	if s.UserClaim == "" {
		return errors.New("user_claim must not be empty")
	}

	if s.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	if s.RequestTimeout <= 0 {
		return errors.New("request_timeout must be positive")
	}

	if s.Issuer == "" && (s.DeviceEndpoint == "" || s.TokenEndpoint == "" || s.UserInfoEndpoint == "") {
		return errors.New("issuer is required when any endpoint is not provided")
	}

	if s.Issuer != "" {
		issuerURL, err := parseEndpointURL(s.Issuer)
		if err != nil {
			return err
		}

		if !s.AllowHTTP && issuerURL.Scheme != "https" {
			return errors.New("issuer must use https unless allow_http=true")
		}
	}

	if s.CAFile != "" {
		if _, err := os.Stat(s.CAFile); err != nil {
			return fmt.Errorf("ca_file not accessible: %w", err)
		}
	}

	return nil
}

// parseDurationArg parses a duration in Go syntax or seconds.
func parseDurationArg(value string) (time.Duration, error) {
	if value == "" {
		return 0, errors.New("empty duration")
	}

	if strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return time.ParseDuration(value)
	}

	seconds, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}

	return time.Duration(seconds) * time.Second, nil
}

// parseEndpointURL validates that a URL has scheme and host.
func parseEndpointURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("empty endpoint")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("endpoint must include scheme and host")
	}

	return u, nil
}

// joinEndpoint joins a base URL with a path using URL semantics.
func joinEndpoint(base *url.URL, path string) (string, error) {
	joined, err := url.JoinPath(base.String(), path)
	if err != nil {
		return "", err
	}

	return joined, nil
}

// validateEndpoint enforces scheme rules for IdP endpoints.
func validateEndpoint(raw string, allowHTTP bool) error {
	u, err := parseEndpointURL(raw)
	if err != nil {
		return err
	}

	if !allowHTTP && u.Scheme != "https" {
		return errors.New("endpoint must use https unless allow_http=true")
	}

	return nil
}

// loadCertPool returns the system cert pool and appends an optional CA file.
func loadCertPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system cert pool: %w", err)
	}

	if caFile == "" {
		return pool, nil
	}

	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca_file: %w", err)
	}

	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, errors.New("no certificates added from ca_file")
	}

	return pool, nil
}
