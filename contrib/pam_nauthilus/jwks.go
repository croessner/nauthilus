package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

var (
	// ErrTokenInactive signals that the introspection endpoint reported the token as inactive.
	ErrTokenInactive = errors.New("token is not active")
	// ErrInvalidSignature signals that the token signature verification failed.
	ErrInvalidSignature = errors.New("token signature verification failed")
)

// jwksResponse mirrors the JSON payload from the JWKS endpoint.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey represents a single JWK entry from the JWKS endpoint.
type jwkKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// introspectionResponse mirrors the JSON payload from the introspection endpoint.
type introspectionResponse struct {
	Active bool `json:"active"`
}

// FetchJWKS retrieves the JWKS key set from the IdP.
func (f *DeviceFlow) FetchJWKS(ctx context.Context) ([]jwkKey, error) {
	reqCtx, cancel := context.WithTimeout(ctx, f.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, f.endpoints.JWKS, nil)
	if err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("jwks request failed: status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("decode jwks response: %w", err)
	}

	return jwks.Keys, nil
}

// VerifyTokenSignature validates the JWT access token signature against the JWKS keys.
func (f *DeviceFlow) VerifyTokenSignature(ctx context.Context, accessToken string) error {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT format: expected three parts")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode JWT header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}

	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("parse JWT header: %w", err)
	}

	if header.Alg != "RS256" {
		return fmt.Errorf("unsupported signing algorithm: %s", header.Alg)
	}

	keys, err := f.FetchJWKS(ctx)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}

	key, err := findSigningKey(keys, header.Kid)
	if err != nil {
		return err
	}

	pubKey, err := parseRSAPublicKey(key)
	if err != nil {
		return err
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])

	if err != nil {
		return fmt.Errorf("decode JWT signature: %w", err)
	}

	hash := sha256.Sum256([]byte(signingInput))

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature); err != nil {
		return ErrInvalidSignature
	}

	return nil
}

// IntrospectToken calls the introspection endpoint and validates the active status.
func (f *DeviceFlow) IntrospectToken(ctx context.Context, accessToken string) error {
	if accessToken == "" {
		return errors.New("access token is required")
	}

	form := make(map[string][]string)
	form["token"] = []string{accessToken}

	body, status, err := f.postForm(ctx, f.endpoints.Introspection, form, true)
	if err != nil {
		return fmt.Errorf("introspection request: %w", err)
	}

	if status != http.StatusOK {
		return fmt.Errorf("introspection request failed: status %d", status)
	}

	var resp introspectionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode introspection response: %w", err)
	}

	if !resp.Active {
		return ErrTokenInactive
	}

	return nil
}

// findSigningKey locates the JWK matching the given kid for signature verification.
func findSigningKey(keys []jwkKey, kid string) (jwkKey, error) {
	for _, key := range keys {
		if key.Kid == kid && key.Use == "sig" {
			return key, nil
		}
	}

	// If no kid match, try the first signing key as fallback.
	if kid == "" {
		for _, key := range keys {
			if key.Use == "sig" {
				return key, nil
			}
		}
	}

	return jwkKey{}, fmt.Errorf("no matching signing key found for kid %q", kid)
}

// parseRSAPublicKey converts a JWK RSA key into a Go rsa.PublicKey.
func parseRSAPublicKey(key jwkKey) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode JWK modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode JWK exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, errors.New("JWK exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
