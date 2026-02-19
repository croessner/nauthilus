// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// deviceAuthResponse represents the JSON response from the device authorization endpoint (RFC 8628 §3.2).
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// deviceTokenResponse represents the JSON response from the token endpoint during device code polling.
type deviceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// registerDeviceCodeRoutes runs the Device Authorization Grant flow (RFC 8628)
// entirely on the console. It requests a device code, displays the verification
// URL and user code, polls the token endpoint, and finally performs JWKS
// verification and a userinfo query.
func registerDeviceCodeRoutes(
	ctx context.Context,
	provider *oidc.Provider,
	providerClaims *ProviderClaims,
	verifier *oidc.IDTokenVerifier,
	scopes []string,
) {
	deviceEndpoint := providerClaims.DeviceAuthorizationEndpoint
	tokenEndpoint := providerClaims.TokenEndpoint

	if deviceEndpoint == "" {
		log.Fatal("Device authorization endpoint not found in provider metadata")
	}

	if tokenEndpoint == "" {
		log.Fatal("Token endpoint not found in provider metadata")
	}

	log.Printf("Starting Device Code flow")
	log.Printf("  Device authorization endpoint: %s", deviceEndpoint)
	log.Printf("  Token endpoint: %s", tokenEndpoint)
	log.Printf("  Requested scopes: %s", strings.Join(scopes, " "))

	// Step 1: Request device and user codes.
	authResp := requestDeviceAuthorization(deviceEndpoint, scopes)

	// Step 2: Display instructions to the user.
	printUserInstructions(authResp)

	// Step 3: Poll the token endpoint until the user completes authorization.
	tokenResp := pollTokenEndpoint(ctx, tokenEndpoint, authResp)

	// Step 4: Verify ID token via JWKS (if openid scope was requested).
	verifyDeviceIDToken(ctx, verifier, providerClaims, tokenResp, scopes)

	// Step 5: Query userinfo endpoint.
	queryUserinfo(ctx, provider, tokenResp)

	// Step 6: Perform introspection (if endpoint available).
	performDeviceIntrospection(providerClaims, tokenResp)

	log.Println("Device Code flow completed successfully")
}

// requestDeviceAuthorization sends a POST to the device authorization endpoint and returns the response.
func requestDeviceAuthorization(deviceEndpoint string, scopes []string) *deviceAuthResponse {
	log.Println("Requesting device authorization...")

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", strings.Join(scopes, " "))

	log.Printf("  POST %s", deviceEndpoint)
	log.Printf("  client_id=%s", clientID)
	log.Printf("  scope=%s", strings.Join(scopes, " "))

	resp, err := http.PostForm(deviceEndpoint, form)
	if err != nil {
		log.Fatalf("Device authorization request failed: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read device authorization response body: %v", err)
	}

	log.Printf("  Response status: %d", resp.StatusCode)
	log.Printf("  Response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Device authorization failed with status %d: %s", resp.StatusCode, string(body))
	}

	authResp := new(deviceAuthResponse)

	if err := json.Unmarshal(body, authResp); err != nil {
		log.Fatalf("Failed to decode device authorization response: %v", err)
	}

	log.Printf("  Device code: %s", authResp.DeviceCode)
	log.Printf("  User code: %s", authResp.UserCode)
	log.Printf("  Verification URI: %s", authResp.VerificationURI)
	log.Printf("  Expires in: %d seconds", authResp.ExpiresIn)
	log.Printf("  Poll interval: %d seconds", authResp.Interval)

	return authResp
}

// printUserInstructions displays the verification URL and user code on the console.
func printUserInstructions(authResp *deviceAuthResponse) {
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println("  DEVICE CODE FLOW - USER ACTION REQUIRED")
	fmt.Println("==================================================")
	fmt.Println()
	fmt.Printf("  1. Open this URL in your browser:\n\n")
	fmt.Printf("     %s\n\n", authResp.VerificationURI)

	if authResp.VerificationURIComplete != "" {
		fmt.Printf("     Or use the complete URL (code pre-filled):\n\n")
		fmt.Printf("     %s\n\n", authResp.VerificationURIComplete)
	}

	fmt.Printf("  2. Enter this code when prompted:\n\n")
	fmt.Printf("     %s\n\n", authResp.UserCode)
	fmt.Println("  3. Authorize the application.")
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Printf("  Waiting for authorization (expires in %d seconds)...\n", authResp.ExpiresIn)
	fmt.Println("==================================================")
	fmt.Println()
}

// pollTokenEndpoint polls the token endpoint at the specified interval until a token is received or the code expires.
func pollTokenEndpoint(ctx context.Context, tokenEndpoint string, authResp *deviceAuthResponse) *deviceTokenResponse {
	interval := time.Duration(authResp.Interval) * time.Second

	if interval == 0 {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)
	attempt := 0

	log.Printf("Polling token endpoint every %s (deadline: %s)", interval, deadline.Format(time.RFC3339))

	for {
		if time.Now().After(deadline) {
			log.Fatal("Device code expired before user completed authorization")
		}

		select {
		case <-ctx.Done():
			log.Fatalf("Context cancelled while polling: %v", ctx.Err())
		case <-time.After(interval):
		}

		attempt++

		log.Printf("Poll attempt #%d...", attempt)

		tokenResp := requestDeviceToken(tokenEndpoint, authResp.DeviceCode)

		switch tokenResp.Error {
		case "":
			log.Println("Token received successfully!")

			return tokenResp

		case "authorization_pending":
			log.Printf("  Authorization pending (user has not yet completed the flow)")

		case "slow_down":
			log.Printf("  Server requested slow down, increasing interval by 5 seconds")

			interval += 5 * time.Second

		case "expired_token":
			log.Fatal("Device code has expired")

		case "access_denied":
			log.Fatal("User denied the authorization request")

		default:
			log.Fatalf("Unexpected error from token endpoint: %s (%s)", tokenResp.Error, tokenResp.ErrorDesc)
		}
	}
}

// requestDeviceToken sends a single token request for the device code grant type.
func requestDeviceToken(tokenEndpoint, deviceCode string) *deviceTokenResponse {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	log.Printf("  POST %s (grant_type=device_code)", tokenEndpoint)

	resp, err := http.PostForm(tokenEndpoint, form)
	if err != nil {
		log.Fatalf("Token request failed: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read token response body: %v", err)
	}

	log.Printf("  Token response status: %d", resp.StatusCode)
	log.Printf("  Token response body: %s", string(body))

	tokenResp := new(deviceTokenResponse)

	if err := json.Unmarshal(body, tokenResp); err != nil {
		log.Fatalf("Failed to decode token response: %v", err)
	}

	return tokenResp
}

// verifyDeviceIDToken verifies the ID token signature via JWKS and logs the claims.
func verifyDeviceIDToken(
	ctx context.Context,
	verifier *oidc.IDTokenVerifier,
	providerClaims *ProviderClaims,
	tokenResp *deviceTokenResponse,
	scopes []string,
) {
	hasOpenID := slices.Contains(scopes, oidc.ScopeOpenID)

	if !hasOpenID {
		log.Println("No openid scope requested — skipping ID token verification")

		return
	}

	if tokenResp.IDToken == "" {
		log.Println("Warning: openid scope was requested but no id_token received")

		return
	}

	log.Println("Verifying ID token signature via JWKS...")
	log.Printf("  Raw ID token length: %d bytes", len(tokenResp.IDToken))

	// Fetch and display JWKS.
	if providerClaims.JwksURI != "" {
		jwksJSON := fetchJWKS(providerClaims.JwksURI)

		if jwksJSON != "" {
			log.Printf("JWKS from %s:", providerClaims.JwksURI)
			fmt.Println(jwksJSON)
		}
	}

	idToken, err := verifier.Verify(ctx, tokenResp.IDToken)
	if err != nil {
		log.Fatalf("ID token verification FAILED: %v", err)
	}

	log.Println("ID token signature verification: SUCCESS")
	log.Printf("  Subject: %s", idToken.Subject)
	log.Printf("  Issuer: %s", idToken.Issuer)
	log.Printf("  Audience: %v", idToken.Audience)
	log.Printf("  Expiry: %s", idToken.Expiry.Format(time.RFC3339))
	log.Printf("  Issued at: %s", idToken.IssuedAt.Format(time.RFC3339))

	// Extract and display all claims.
	var claims json.RawMessage

	if err := idToken.Claims(&claims); err != nil {
		log.Printf("Warning: Failed to extract ID token claims: %v", err)

		return
	}

	prettyPrintJSON("ID Token Claims", claims)
}

// queryUserinfo calls the provider's userinfo endpoint and displays the result.
func queryUserinfo(ctx context.Context, provider *oidc.Provider, tokenResp *deviceTokenResponse) {
	if provider.UserInfoEndpoint() == "" {
		log.Println("Userinfo endpoint not available — skipping")

		return
	}

	log.Printf("Querying userinfo endpoint: %s", provider.UserInfoEndpoint())

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
	})

	userInfo, err := provider.UserInfo(ctx, tokenSource)
	if err != nil {
		log.Fatalf("Userinfo request failed: %v", err)
	}

	log.Println("Userinfo request: SUCCESS")
	log.Printf("  Subject: %s", userInfo.Subject)
	log.Printf("  Email: %s", userInfo.Email)
	log.Printf("  Email verified: %v", userInfo.EmailVerified)
	log.Printf("  Profile: %s", userInfo.Profile)

	var claims json.RawMessage

	if err := userInfo.Claims(&claims); err != nil {
		log.Printf("Warning: Failed to extract userinfo claims: %v", err)

		return
	}

	prettyPrintJSON("Userinfo Claims", claims)
}

// performDeviceIntrospection runs token introspection if the endpoint is available.
func performDeviceIntrospection(providerClaims *ProviderClaims, tokenResp *deviceTokenResponse) {
	if providerClaims.IntrospectionEndpoint == "" {
		log.Println("Introspection endpoint not available — skipping")

		return
	}

	result := performIntrospection(providerClaims.IntrospectionEndpoint, tokenResp.AccessToken)
	if result != nil {
		prettyPrintJSON("Introspection Result", *result)
	}
}

// prettyPrintJSON formats and prints a JSON value with a label to the console.
func prettyPrintJSON(label string, data json.RawMessage) {
	indented, err := json.MarshalIndent(data, "  ", "    ")
	if err != nil {
		log.Printf("%s (raw): %s", label, string(data))

		return
	}

	fmt.Printf("\n  %s:\n  %s\n\n", label, string(indented))
}
