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
	"html/template"
	"log"
	"net/http"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// registerAuthorizationCodeRoutes registers the HTTP handlers for the
// Authorization Code Grant flow (login redirect, OAuth2 callback, logout endpoints).
func registerAuthorizationCodeRoutes(
	ctx context.Context,
	provider *oidc.Provider,
	providerClaims *ProviderClaims,
	verifier *oidc.IDTokenVerifier,
	tmpl *template.Template,
	scopes []string,
) {
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("http://%s/oauth2", listenAddr),
		Scopes:       scopes,
	}

	log.Printf("Client configuration: ID=%s, RedirectURL=%s, Scopes=%v", clientID, oauth2Config.RedirectURL, oauth2Config.Scopes)

	http.HandleFunc("/", handleAuthCodeLogin(&oauth2Config))
	http.HandleFunc("/oauth2", handleAuthCodeCallback(ctx, &oauth2Config, providerClaims, verifier, tmpl, scopes))
	http.HandleFunc("/frontchannel-logout", handleFrontChannelLogout)
	http.HandleFunc("/backchannel-logout", handleBackChannelLogout(ctx, verifier))
	http.HandleFunc("/logout-callback", handleLogoutCallback)
}

// handleAuthCodeLogin returns the handler that initiates the Authorization Code flow
// by generating state/nonce cookies and redirecting the user to the authorization endpoint.
func handleAuthCodeLogin(oauth2Config *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on '/' - Starting OIDC flow")

		state, err := randString(16)
		if err != nil {
			log.Printf("Error generating state: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)

			return
		}

		nonce, err := randString(16)
		if err != nil {
			log.Printf("Error generating nonce: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)

			return
		}

		log.Printf("Generated state=%s, nonce=%s", state, nonce)

		setCallbackCookie(w, "state", state)
		setCallbackCookie(w, "nonce", nonce)

		authURL := oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
		log.Printf("Redirecting to: %s", authURL)

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// handleAuthCodeCallback returns the handler that processes the authorization server's
// callback, exchanges the code for tokens, verifies the ID token, and renders the result page.
func handleAuthCodeCallback(
	ctx context.Context,
	oauth2Config *oauth2.Config,
	providerClaims *ProviderClaims,
	verifier *oidc.IDTokenVerifier,
	tmpl *template.Template,
	scopes []string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received callback on '/oauth2'")

		rawIDToken, signatureVerified, resp, ok := exchangeAndVerify(ctx, w, r, oauth2Config, verifier, scopes)
		if !ok {
			return
		}

		deleteCallbackCookie(w, "state")
		deleteCallbackCookie(w, "nonce")

		resp.IntrospectionResult = performIntrospection(providerClaims.IntrospectionEndpoint, resp.OAuth2Token.AccessToken)

		renderSuccessPage(w, tmpl, providerClaims, rawIDToken, signatureVerified, resp)
	}
}

// exchangeAndVerify performs the token exchange and optional ID token verification.
// It returns the raw ID token string, whether the signature was verified, the
// response struct, and a boolean indicating success. On failure it writes an HTTP
// error and returns ok=false.
func exchangeAndVerify(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	oauth2Config *oauth2.Config,
	verifier *oidc.IDTokenVerifier,
	scopes []string,
) (string, bool, *tokenResponse, bool) {
	if ok := validateState(w, r); !ok {
		return "", false, nil, false
	}

	queryCode := r.URL.Query().Get("code")

	log.Println("Exchanging authorization code for tokens...")

	oauth2Token, err := oauth2Config.Exchange(ctx, queryCode)
	if err != nil {
		log.Printf("Token exchange failed: %v", err)
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)

		return "", false, nil, false
	}

	log.Println("Token exchange successful")

	// Per OIDC Core 1.0 §3.1.2.1: id_token is only present when "openid" scope was requested.
	hasOpenID := slices.Contains(scopes, oidc.ScopeOpenID)
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	signatureVerified := false

	resp := &tokenResponse{OAuth2Token: oauth2Token}

	if hasOpenID {
		idTokenClaims, verified, ok := verifyIDToken(ctx, w, r, verifier, rawIDToken)
		if !ok {
			return "", false, nil, false
		}

		signatureVerified = verified
		resp.IDTokenClaims = idTokenClaims
	} else {
		log.Println("Pure OAuth 2.0 flow (no openid scope) - skipping ID token verification")
	}

	return rawIDToken, signatureVerified, resp, true
}

// validateState checks that the state query parameter matches the state cookie.
func validateState(w http.ResponseWriter, r *http.Request) bool {
	queryState := r.URL.Query().Get("state")
	queryCode := r.URL.Query().Get("code")

	log.Printf("Query parameters: state=%s, code=%s", queryState, queryCode)

	stateCookie, err := r.Cookie("state")
	if err != nil {
		log.Printf("State cookie missing: %v", err)
		http.Error(w, "state not found", http.StatusBadRequest)

		return false
	}

	log.Printf("Cookie state=%s", stateCookie.Value)

	if queryState != stateCookie.Value {
		log.Printf("State mismatch: query=%s, cookie=%s", queryState, stateCookie.Value)
		http.Error(w, "state did not match", http.StatusBadRequest)

		return false
	}

	return true
}

// verifyIDToken verifies the raw ID token, checks the nonce, and extracts claims.
func verifyIDToken(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	verifier *oidc.IDTokenVerifier,
	rawIDToken string,
) (*json.RawMessage, bool, bool) {
	if rawIDToken == "" {
		log.Println("ID token missing in exchange response despite openid scope")
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)

		return nil, false, false
	}

	log.Printf("Raw ID Token received (length: %d)", len(rawIDToken))
	log.Println("Verifying ID Token...")

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("ID Token verification failed: %v", err)
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)

		return nil, false, false
	}

	log.Println("ID Token verification successful")

	nonceCookie, err := r.Cookie("nonce")
	if err != nil {
		log.Printf("Nonce cookie missing: %v", err)
		http.Error(w, "nonce not found", http.StatusBadRequest)

		return nil, false, false
	}

	log.Printf("Cookie nonce=%s, Token nonce=%s", nonceCookie.Value, idToken.Nonce)

	if idToken.Nonce != nonceCookie.Value {
		log.Printf("Nonce mismatch: token=%s, cookie=%s", idToken.Nonce, nonceCookie.Value)
		http.Error(w, "nonce did not match", http.StatusBadRequest)

		return nil, false, false
	}

	log.Println("Extracting claims from ID Token...")

	idTokenClaims := new(json.RawMessage)

	if err := idToken.Claims(idTokenClaims); err != nil {
		log.Printf("Failed to extract claims: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return nil, false, false
	}

	log.Println("Claims extracted successfully")

	return idTokenClaims, true, true
}

// tokenResponse holds the OAuth2 token and optional claims/introspection results.
type tokenResponse struct {
	OAuth2Token         *oauth2.Token
	IDTokenClaims       *json.RawMessage `json:",omitzero"`
	IntrospectionResult *json.RawMessage `json:",omitzero"`
}

// renderSuccessPage marshals the token response and renders the HTML success page.
func renderSuccessPage(
	w http.ResponseWriter,
	tmpl *template.Template,
	providerClaims *ProviderClaims,
	rawIDToken string,
	signatureVerified bool,
	resp *tokenResponse,
) {
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	log.Printf("Sending response back to browser (%d bytes)", len(data))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	err = tmpl.Execute(w, struct {
		JSON                  string
		LogoutURL             string
		TwoFAHomeURL          string
		SignatureVerified     bool
		JWKS                  string
		JwksURI               string
		FrontChannelLogoutURI string
		BackChannelLogoutURI  string
	}{
		JSON:                  string(data),
		LogoutURL:             buildLogoutURL(providerClaims.EndSessionEndpoint, rawIDToken),
		TwoFAHomeURL:          build2FAHomeURL(),
		SignatureVerified:     signatureVerified,
		JWKS:                  fetchJWKS(providerClaims.JwksURI),
		JwksURI:               providerClaims.JwksURI,
		FrontChannelLogoutURI: fmt.Sprintf("http://%s/frontchannel-logout", listenAddr),
		BackChannelLogoutURI:  fmt.Sprintf("http://%s/backchannel-logout", listenAddr),
	})
	if err != nil {
		log.Printf("Failed to render template: %v", err)
	}
}

// handleFrontChannelLogout processes front-channel logout requests from the IdP.
func handleFrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request on '/frontchannel-logout'")

	iss := r.URL.Query().Get("iss")
	sid := r.URL.Query().Get("sid")

	log.Printf("Front-channel logout params: iss=%s, sid=%s", iss, sid)

	deleteCallbackCookie(w, "state")
	deleteCallbackCookie(w, "nonce")
	clearSessionCookies(w)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Front-channel logout processed")
}

// handleBackChannelLogout returns a handler that processes back-channel logout tokens.
func handleBackChannelLogout(ctx context.Context, verifier *oidc.IDTokenVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on '/backchannel-logout'")

		if err := r.ParseForm(); err != nil {
			log.Printf("Failed to parse form: %v", err)
			http.Error(w, "Failed to parse form", http.StatusBadRequest)

			return
		}

		logoutToken := r.FormValue("logout_token")

		if logoutToken == "" {
			log.Println("Missing logout_token")
			http.Error(w, "Missing logout_token", http.StatusBadRequest)

			return
		}

		log.Printf("Received logout_token: %s", logoutToken)

		token, err := verifier.Verify(ctx, logoutToken)
		if err != nil {
			log.Printf("Failed to verify logout_token: %v", err)
			http.Error(w, "Invalid logout_token", http.StatusBadRequest)

			return
		}

		var claims struct {
			Events map[string]any `json:"events"`
			Sid    string         `json:"sid"`
			Nonce  string         `json:"nonce"`
		}

		if err := token.Claims(&claims); err != nil {
			log.Printf("Failed to extract logout_token claims: %v", err)
			http.Error(w, "Invalid logout_token claims", http.StatusBadRequest)

			return
		}

		if claims.Nonce != "" {
			log.Println("logout_token contains nonce, which is forbidden")
			http.Error(w, "logout_token contains nonce", http.StatusBadRequest)

			return
		}

		if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
			log.Println("logout_token missing backchannel-logout event")
			http.Error(w, "Missing backchannel-logout event", http.StatusBadRequest)

			return
		}

		log.Printf("Back-channel logout successful for sid: %s", claims.Sid)
		w.WriteHeader(http.StatusOK)
	}
}

// handleLogoutCallback handles the post-logout redirect from the IdP.
func handleLogoutCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request on '/logout-callback'")

	clearSessionCookies(w)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head><title>Logged Out</title><style>body{font-family:sans-serif;margin:2em;}</style></head>
		<body>
			<h1>Successfully Logged Out</h1>
			<p>You have been redirected back after logging out from the provider.</p>
			<p><a href="/">Start over</a></p>
		</body>
		</html>
	`)
}
