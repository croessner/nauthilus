package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrTimeout signals that the device authorization expired or exceeded the timeout.
	ErrTimeout = errors.New("authentication timed out")
	// ErrAccessDenied signals that the user denied the authorization request.
	ErrAccessDenied = errors.New("access denied")
	// ErrUserMismatch signals that the userinfo claim does not match the PAM username.
	ErrUserMismatch = errors.New("user claim does not match PAM user")
)

// Clock abstracts time for testable polling.
type Clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

// systemClock is the production clock implementation.
type systemClock struct{}

// Now returns the current time.
func (systemClock) Now() time.Time {
	return time.Now()
}

// Sleep pauses execution for the given duration.
func (systemClock) Sleep(d time.Duration) {
	time.Sleep(d)
}

// DeviceFlow coordinates the RFC 8628 device authorization flow.
type DeviceFlow struct {
	client         *http.Client
	endpoints      EndpointSet
	clientID       string
	clientSecret   string
	scope          string
	userClaim      string
	requestTimeout time.Duration
	clock          Clock
}

// DeviceAuthorization contains the response values from the device endpoint.
type DeviceAuthorization struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	Interval                time.Duration
	ExpiresIn               time.Duration
}

// TokenResponse contains the access token data returned by the token endpoint.
type TokenResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   time.Duration
}

// deviceResponse mirrors the JSON payload from the device endpoint.
type deviceResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}

// tokenResponse mirrors the JSON payload from the token endpoint.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// NewDeviceFlow builds a DeviceFlow with validated endpoints and secure defaults.
func NewDeviceFlow(settings Settings, client *http.Client, clock Clock) (*DeviceFlow, error) {
	endpoints, err := settings.Endpoints()
	if err != nil {
		return nil, err
	}

	if client == nil {
		client, err = newHTTPClient(settings)
		if err != nil {
			return nil, err
		}
	}

	if clock == nil {
		clock = systemClock{}
	}

	return &DeviceFlow{
		client:         client,
		endpoints:      endpoints,
		clientID:       settings.ClientID,
		clientSecret:   settings.ClientSecret,
		scope:          settings.Scope,
		userClaim:      settings.UserClaim,
		requestTimeout: settings.RequestTimeout,
		clock:          clock,
	}, nil
}

// newHTTPClient configures a TLS-hardened HTTP client for IdP calls.
func newHTTPClient(settings Settings) (*http.Client, error) {
	pool, err := loadCertPool(settings.CAFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	if settings.TLSServerName != "" {
		tlsConfig.ServerName = settings.TLSServerName
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// StartDeviceAuthorization requests a device code and user code from the IdP.
func (f *DeviceFlow) StartDeviceAuthorization(ctx context.Context) (DeviceAuthorization, error) {
	form := url.Values{}
	form.Set("client_id", f.clientID)
	form.Set("scope", f.scope)

	body, status, err := f.postForm(ctx, f.endpoints.Device, form, false)
	if err != nil {
		return DeviceAuthorization{}, err
	}

	var resp deviceResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return DeviceAuthorization{}, fmt.Errorf("decode device response: %w", err)
	}

	if resp.Error != "" {
		return DeviceAuthorization{}, fmt.Errorf("device authorization error: %s", resp.Error)
	}

	if status != http.StatusOK {
		return DeviceAuthorization{}, fmt.Errorf("device authorization failed: status %d", status)
	}

	if resp.DeviceCode == "" || resp.UserCode == "" || resp.VerificationURI == "" {
		return DeviceAuthorization{}, errors.New("device authorization response missing required fields")
	}

	interval := time.Duration(resp.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	return DeviceAuthorization{
		DeviceCode:              resp.DeviceCode,
		UserCode:                resp.UserCode,
		VerificationURI:         resp.VerificationURI,
		VerificationURIComplete: resp.VerificationURIComplete,
		Interval:                interval,
		ExpiresIn:               time.Duration(resp.ExpiresIn) * time.Second,
	}, nil
}

// PollToken polls the token endpoint until authorization completes or times out.
func (f *DeviceFlow) PollToken(ctx context.Context, deviceCode string, interval time.Duration, deadline time.Time) (TokenResponse, error) {
	if deviceCode == "" {
		return TokenResponse{}, errors.New("device code is required")
	}

	if interval <= 0 {
		interval = 5 * time.Second
	}

	for {
		if !deadline.IsZero() && f.clock.Now().After(deadline) {
			return TokenResponse{}, ErrTimeout
		}

		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return TokenResponse{}, ErrTimeout
			}

			return TokenResponse{}, err
		}

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("device_code", deviceCode)

		body, status, err := f.postForm(ctx, f.endpoints.Token, form, true)
		if err != nil {
			return TokenResponse{}, err
		}

		var resp tokenResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return TokenResponse{}, fmt.Errorf("decode token response: %w", err)
		}

		if resp.Error != "" {
			switch resp.Error {
			case "authorization_pending":
				f.clock.Sleep(interval)
				continue
			case "slow_down":
				interval += 5 * time.Second
				f.clock.Sleep(interval)
				continue
			case "access_denied":
				return TokenResponse{}, ErrAccessDenied
			case "expired_token":
				return TokenResponse{}, ErrTimeout
			default:
				return TokenResponse{}, fmt.Errorf("token error: %s", resp.Error)
			}
		}

		if status != http.StatusOK {
			return TokenResponse{}, fmt.Errorf("token request failed: status %d", status)
		}

		if resp.AccessToken == "" {
			return TokenResponse{}, errors.New("token response missing access_token")
		}

		if resp.TokenType != "" && !strings.EqualFold(resp.TokenType, "bearer") {
			return TokenResponse{}, fmt.Errorf("unsupported token type: %s", resp.TokenType)
		}

		return TokenResponse{
			AccessToken: resp.AccessToken,
			TokenType:   resp.TokenType,
			ExpiresIn:   time.Duration(resp.ExpiresIn) * time.Second,
		}, nil
	}
}

// FetchUserInfo queries the userinfo endpoint and returns the claims map.
func (f *DeviceFlow) FetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}

	reqCtx, cancel := context.WithTimeout(ctx, f.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, f.endpoints.UserInfo, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: status %d", resp.StatusCode)
	}

	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("decode userinfo response: %w", err)
	}

	return claims, nil
}

// VerifyUser compares the configured claim with the PAM username using a constant-time check.
func (f *DeviceFlow) VerifyUser(claims map[string]any, username string) error {
	claimRaw, ok := claims[f.userClaim]
	if !ok {
		return fmt.Errorf("claim %s not found", f.userClaim)
	}

	claimValue, ok := claimRaw.(string)
	if !ok {
		return fmt.Errorf("claim %s is not a string", f.userClaim)
	}

	if subtle.ConstantTimeCompare([]byte(claimValue), []byte(username)) != 1 {
		return ErrUserMismatch
	}

	return nil
}

// postForm sends a form-encoded request to the IdP and returns body and status.
func (f *DeviceFlow) postForm(ctx context.Context, endpoint string, form url.Values, useBasicAuth bool) ([]byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, f.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if useBasicAuth {
		req.SetBasicAuth(f.clientID, f.clientSecret)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}
