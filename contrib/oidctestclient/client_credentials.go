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
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// clientCredentialsTokenResponse represents the JSON response from the token endpoint
// for the Client Credentials Grant (RFC 6749 §4.4.3).
type clientCredentialsTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// registerClientCredentialsRoutes runs the Client Credentials Grant flow (RFC 6749 §4.4)
// entirely on the console. It requests a token using client credentials, performs JWKS
// verification, and runs token introspection.
func registerClientCredentialsRoutes(
	ctx context.Context,
	_ *oidc.Provider,
	providerClaims *ProviderClaims,
	verifier *oidc.IDTokenVerifier,
	scopes []string,
) {
	tokenEndpoint := providerClaims.TokenEndpoint

	if tokenEndpoint == "" {
		log.Fatal("Token endpoint not found in provider metadata")
	}

	log.Printf("Starting Client Credentials flow")
	log.Printf("  Token endpoint: %s", tokenEndpoint)
	log.Printf("  Requested scopes: %s", strings.Join(scopes, " "))

	// Step 1: Request an access token using client credentials.
	tokenResp := requestClientCredentialsToken(tokenEndpoint, scopes)

	// Step 2: Verify the access token signature via JWKS.
	verifyClientCredentialsToken(ctx, verifier, providerClaims, tokenResp)

	// Step 3: Perform introspection (if endpoint available).
	performClientCredentialsIntrospection(providerClaims, tokenResp)

	log.Println("Client Credentials flow completed successfully")
}

// requestClientCredentialsToken sends a POST to the token endpoint with the
// client_credentials grant type and returns the token response.
func requestClientCredentialsToken(tokenEndpoint string, scopes []string) *clientCredentialsTokenResponse {
	log.Println("Requesting access token with client credentials...")

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", strings.Join(scopes, " "))

	log.Printf("  POST %s", tokenEndpoint)
	log.Printf("  client_id=%s", clientID)
	log.Printf("  scope=%s", strings.Join(scopes, " "))

	resp, err := http.PostForm(tokenEndpoint, form)
	if err != nil {
		log.Fatalf("Token request failed: %v", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read token response body: %v", err)
	}

	log.Printf("  Response status: %d", resp.StatusCode)
	log.Printf("  Response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	tokenResp := new(clientCredentialsTokenResponse)

	if err := json.Unmarshal(body, tokenResp); err != nil {
		log.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResp.Error != "" {
		log.Fatalf("Token endpoint returned error: %s (%s)", tokenResp.Error, tokenResp.ErrorDesc)
	}

	log.Println("Access token received successfully!")
	log.Printf("  Token type: %s", tokenResp.TokenType)
	log.Printf("  Expires in: %d seconds", tokenResp.ExpiresIn)
	log.Printf("  Scope: %s", tokenResp.Scope)

	return tokenResp
}

// verifyClientCredentialsToken verifies the access token signature via JWKS and logs the result.
func verifyClientCredentialsToken(
	ctx context.Context,
	verifier *oidc.IDTokenVerifier,
	providerClaims *ProviderClaims,
	tokenResp *clientCredentialsTokenResponse,
) {
	if tokenResp.AccessToken == "" {
		log.Println("Warning: no access token received — skipping JWKS verification")

		return
	}

	log.Println("Verifying access token signature via JWKS...")
	log.Printf("  Raw access token length: %d bytes", len(tokenResp.AccessToken))

	// Fetch and display JWKS.
	if providerClaims.JwksURI != "" {
		jwksJSON := fetchJWKS(providerClaims.JwksURI)

		if jwksJSON != "" {
			log.Printf("JWKS from %s:", providerClaims.JwksURI)
			fmt.Println(jwksJSON)
		}
	}

	token, err := verifier.Verify(ctx, tokenResp.AccessToken)
	if err != nil {
		log.Printf("Access token verification FAILED: %v", err)
		log.Println("Note: Client Credentials tokens may be opaque (not JWT) — verification failure can be expected")

		return
	}

	log.Println("Access token signature verification: SUCCESS")
	log.Printf("  Subject: %s", token.Subject)
	log.Printf("  Issuer: %s", token.Issuer)
	log.Printf("  Audience: %v", token.Audience)

	// Extract and display all claims.
	var claims json.RawMessage

	if err := token.Claims(&claims); err != nil {
		log.Printf("Warning: Failed to extract access token claims: %v", err)

		return
	}

	prettyPrintJSON("Access Token Claims", claims)
}

// performClientCredentialsIntrospection runs token introspection if the endpoint is available.
func performClientCredentialsIntrospection(providerClaims *ProviderClaims, tokenResp *clientCredentialsTokenResponse) {
	if providerClaims.IntrospectionEndpoint == "" {
		log.Println("Introspection endpoint not available — skipping")

		return
	}

	result := performIntrospection(providerClaims.IntrospectionEndpoint, tokenResp.AccessToken)
	if result != nil {
		prettyPrintJSON("Introspection Result", *result)
	}
}
