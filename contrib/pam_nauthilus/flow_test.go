package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time {
	return c.now
}

func (c *testClock) Sleep(d time.Duration) {
	c.now = c.now.Add(d)
}

func TestDeviceFlowSuccess(t *testing.T) {
	clock := &testClock{now: time.Unix(0, 0)}
	requests := struct {
		TokenCalls int
	}{}

	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/device", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		if r.FormValue("client_id") != "client" {
			t.Fatalf("unexpected client_id: %s", r.FormValue("client_id"))
		}

		if r.FormValue("scope") != "openid" {
			t.Fatalf("unexpected scope: %s", r.FormValue("scope"))
		}

		_ = json.NewEncoder(w).Encode(deviceResponse{
			DeviceCode:      "dev-code",
			UserCode:        "USER-123",
			VerificationURI: "https://example.test/verify",
			ExpiresIn:       60,
			Interval:        1,
		})
	})

	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		requests.TokenCalls++

		id, secret, ok := r.BasicAuth()
		if !ok {
			t.Fatalf("expected basic auth")
		}

		if id != "client" || secret != "secret" {
			t.Fatalf("unexpected basic auth credentials")
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		if r.FormValue("device_code") != "dev-code" {
			t.Fatalf("unexpected device_code")
		}

		if requests.TokenCalls == 1 {
			_ = json.NewEncoder(w).Encode(tokenResponse{Error: "authorization_pending"})

			return
		}

		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "token", TokenType: "Bearer", ExpiresIn: 30})
	})

	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected authorization header: %s", got)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"preferred_username": "alice"})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	settings := Settings{
		Issuer:         server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        2 * time.Minute,
		RequestTimeout: 5 * time.Second,
		UserClaim:      "preferred_username",
		AllowHTTP:      true,
	}

	flow, err := NewDeviceFlow(settings, server.Client(), clock)
	if err != nil {
		t.Fatalf("new flow: %v", err)
	}

	ctx := t.Context()
	device, err := flow.StartDeviceAuthorization(ctx)
	if err != nil {
		t.Fatalf("start device: %v", err)
	}

	deadline := clock.Now().Add(device.ExpiresIn)
	token, err := flow.PollToken(ctx, device.DeviceCode, device.Interval, deadline)
	if err != nil {
		t.Fatalf("poll token: %v", err)
	}

	claims, err := flow.FetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("fetch userinfo: %v", err)
	}

	if err := flow.VerifyUser(claims, "alice"); err != nil {
		t.Fatalf("verify user: %v", err)
	}
}

func TestDeviceFlowUserMismatch(t *testing.T) {
	clock := &testClock{now: time.Unix(0, 0)}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(deviceResponse{
			DeviceCode:      "dev-code",
			UserCode:        "USER-123",
			VerificationURI: "https://example.test/verify",
			ExpiresIn:       60,
			Interval:        1,
		})
	})

	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "token", TokenType: "Bearer", ExpiresIn: 30})
	})

	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"preferred_username": "bob"})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	settings := Settings{
		Issuer:         server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        2 * time.Minute,
		RequestTimeout: 5 * time.Second,
		UserClaim:      "preferred_username",
		AllowHTTP:      true,
	}

	flow, err := NewDeviceFlow(settings, server.Client(), clock)
	if err != nil {
		t.Fatalf("new flow: %v", err)
	}

	ctx := t.Context()
	device, err := flow.StartDeviceAuthorization(ctx)
	if err != nil {
		t.Fatalf("start device: %v", err)
	}

	deadline := clock.Now().Add(device.ExpiresIn)
	token, err := flow.PollToken(ctx, device.DeviceCode, device.Interval, deadline)
	if err != nil {
		t.Fatalf("poll token: %v", err)
	}

	claims, err := flow.FetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("fetch userinfo: %v", err)
	}

	if err := flow.VerifyUser(claims, "alice"); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("expected user mismatch, got %v", err)
	}
}

func TestDeviceFlowAccessDenied(t *testing.T) {
	clock := &testClock{now: time.Unix(0, 0)}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(deviceResponse{
			DeviceCode:      "dev-code",
			UserCode:        "USER-123",
			VerificationURI: "https://example.test/verify",
			ExpiresIn:       60,
			Interval:        1,
		})
	})

	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResponse{Error: "access_denied"})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	settings := Settings{
		Issuer:         server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        2 * time.Minute,
		RequestTimeout: 5 * time.Second,
		UserClaim:      "preferred_username",
		AllowHTTP:      true,
	}

	flow, err := NewDeviceFlow(settings, server.Client(), clock)
	if err != nil {
		t.Fatalf("new flow: %v", err)
	}

	ctx := t.Context()
	device, err := flow.StartDeviceAuthorization(ctx)
	if err != nil {
		t.Fatalf("start device: %v", err)
	}

	deadline := clock.Now().Add(device.ExpiresIn)
	_, err = flow.PollToken(ctx, device.DeviceCode, device.Interval, deadline)
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("expected access denied, got %v", err)
	}
}

func TestParseDurationArgSeconds(t *testing.T) {
	dur, err := parseDurationArg("30")
	if err != nil {
		t.Fatalf("parse duration: %v", err)
	}

	if dur != 30*time.Second {
		t.Fatalf("unexpected duration: %s", dur)
	}
}

func TestParseDurationArgDuration(t *testing.T) {
	dur, err := parseDurationArg("1500ms")
	if err != nil {
		t.Fatalf("parse duration: %v", err)
	}

	if dur != 1500*time.Millisecond {
		t.Fatalf("unexpected duration: %s", dur)
	}
}

func TestEndpointsFromIssuer(t *testing.T) {
	settings := Settings{
		Issuer:         "https://example.test",
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        time.Minute,
		RequestTimeout: time.Second,
		UserClaim:      "preferred_username",
	}

	endpoints, err := settings.Endpoints()
	if err != nil {
		t.Fatalf("endpoints: %v", err)
	}

	if endpoints.Device != "https://example.test/oidc/device" {
		t.Fatalf("unexpected device endpoint: %s", endpoints.Device)
	}
}

func TestEndpointsCustom(t *testing.T) {
	settings := Settings{
		DeviceEndpoint:        "https://idp.test/device",
		TokenEndpoint:         "https://idp.test/token",
		UserInfoEndpoint:      "https://idp.test/userinfo",
		JWKSEndpoint:          "https://idp.test/jwks",
		IntrospectionEndpoint: "https://idp.test/introspect",
		ClientID:              "client",
		ClientSecret:          "secret",
		Scope:                 "openid",
		Timeout:               time.Minute,
		RequestTimeout:        time.Second,
		UserClaim:             "preferred_username",
	}

	endpoints, err := settings.Endpoints()
	if err != nil {
		t.Fatalf("endpoints: %v", err)
	}

	if endpoints.Token != "https://idp.test/token" {
		t.Fatalf("unexpected token endpoint: %s", endpoints.Token)
	}
}

func TestValidateEndpointHTTP(t *testing.T) {
	if err := validateEndpoint("http://example.test", false); err == nil {
		t.Fatalf("expected error for http endpoint without allow_http")
	}

	if err := validateEndpoint("http://example.test", true); err != nil {
		t.Fatalf("unexpected error for http endpoint: %v", err)
	}
}

func TestEndpointsRequiresIssuerWhenMissing(t *testing.T) {
	settings := Settings{
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        time.Minute,
		RequestTimeout: time.Second,
		UserClaim:      "preferred_username",
	}

	if _, err := settings.Endpoints(); err == nil {
		t.Fatalf("expected error when issuer is missing")
	}
}

func TestValidateEndpointInvalid(t *testing.T) {
	if err := validateEndpoint("://invalid", true); err == nil {
		t.Fatalf("expected error for invalid endpoint")
	}
}

func TestStartDeviceAuthorizationRejectsErrorResponse(t *testing.T) {
	clock := &testClock{now: time.Unix(0, 0)}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(deviceResponse{Error: "invalid_client"})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	settings := Settings{
		Issuer:         server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        time.Minute,
		RequestTimeout: time.Second,
		UserClaim:      "preferred_username",
		AllowHTTP:      true,
	}

	flow, err := NewDeviceFlow(settings, server.Client(), clock)
	if err != nil {
		t.Fatalf("new flow: %v", err)
	}

	if _, err := flow.StartDeviceAuthorization(t.Context()); err == nil {
		t.Fatalf("expected error response")
	}
}

func TestPostFormEncodesValues(t *testing.T) {
	clock := &testClock{now: time.Unix(0, 0)}
	var received url.Values
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		received = r.Form
		_ = json.NewEncoder(w).Encode(deviceResponse{
			DeviceCode:      "dev-code",
			UserCode:        "USER-123",
			VerificationURI: "https://example.test/verify",
			ExpiresIn:       60,
			Interval:        1,
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	settings := Settings{
		Issuer:         server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        time.Minute,
		RequestTimeout: time.Second,
		UserClaim:      "preferred_username",
		AllowHTTP:      true,
	}

	flow, err := NewDeviceFlow(settings, server.Client(), clock)
	if err != nil {
		t.Fatalf("new flow: %v", err)
	}

	if _, err := flow.StartDeviceAuthorization(t.Context()); err != nil {
		t.Fatalf("start device: %v", err)
	}

	if received.Get("client_id") != "client" {
		t.Fatalf("unexpected client_id: %s", received.Get("client_id"))
	}
}
