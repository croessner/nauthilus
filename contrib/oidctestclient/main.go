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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/util"
	"golang.org/x/oauth2"
)

// defaultScopes defines the default OIDC scopes used when the OAUTH2_SCOPES environment variable is not set.
var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline", "offline_access", "nauthilus:mfa:manage"}

var (
	openIDProvider = os.Getenv("OPENID_PROVIDER")
	clientID       = os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret   = os.Getenv("OAUTH2_CLIENT_SECRET")
)

const successPageTmpl = `
<!DOCTYPE html>
<html>
<head>
    <title>OIDC Test Client - Success</title>
    <style>
        body { font-family: sans-serif; margin: 2em; line-height: 1.5; background-color: #f9f9f9; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        pre { background: #f4f4f4; padding: 1em; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd; font-size: 0.9em; }
        h1 { color: #333; }
        h2 { color: #555; margin-top: 1.5em; border-bottom: 2px solid #eee; padding-bottom: 0.3em; }
        .status-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }
        .status-success { background-color: #dff0d8; color: #3c763d; border: 1px solid #d6e9c6; }
        .status-error { background-color: #f2dede; color: #a94442; border: 1px solid #ebccd1; }
        .logout-btn {
            display: inline-block;
            padding: 10px 20px;
            background-color: #d9534f;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
            font-weight: bold;
        }
        .logout-btn:hover { background-color: #c9302c; }
        .twofa-btn {
            display: inline-block;
            padding: 10px 20px;
            background-color: #5cb85c;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
            margin-right: 10px;
            font-weight: bold;
        }
        .twofa-btn:hover { background-color: #4cae4c; }
        .section { margin-bottom: 2em; }
        .info-box {
            background-color: #e7f3fe;
            border-left: 6px solid #2196F3;
            margin-bottom: 15px;
            padding: 4px 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Successful</h1>

        <div class="info-box">
            <p><strong>Configuring Logout in Nauthilus:</strong><br>
            Front-channel Logout URI: <code>{{.FrontChannelLogoutURI}}</code><br>
            Back-channel Logout URI: <code>{{.BackChannelLogoutURI}}</code></p>
        </div>

        <div class="section">
            <h2>Signature Verification</h2>
            {{if .SignatureVerified}}
                <span class="status-badge status-success">✓ Signature Verified</span>
                <p>The ID Token signature has been successfully verified against the provider's public keys.</p>
            {{else}}
                <span class="status-badge status-error">✗ Verification Failed</span>
                <p>Could not verify the ID Token signature.</p>
            {{end}}
        </div>

        <div class="section">
            <h2>JWKS (Public Keys)</h2>
            <p>Discovered from: <code>{{.JwksURI}}</code></p>
            <pre>{{.JWKS}}</pre>
        </div>

        <div class="section">
            <h2>Tokens & Claims</h2>
            <p>The following tokens and claims were received from the provider:</p>
            <pre>{{.JSON}}</pre>
        </div>

        <div style="margin-top: 20px;">
            {{if .TwoFAHomeURL}}
                <a href="{{.TwoFAHomeURL}}" class="twofa-btn">Manage 2FA (TOTP/WebAuthn)</a>
            {{end}}
            {{if .LogoutURL}}
                <a href="{{.LogoutURL}}" class="logout-btn">Logout from Provider</a>
            {{else}}
                <p><em>Note: End session endpoint not found in provider metadata. Logout link unavailable.</em></p>
            {{end}}
        </div>
    </div>
</body>
</html>
`

// parseScopesFromEnv reads the OAUTH2_SCOPES environment variable and returns
// the configured scopes as a string slice. Scopes are separated by commas or
// spaces. If the variable is unset or empty, defaultScopes is returned.
func parseScopesFromEnv() []string {
	raw := os.Getenv("OAUTH2_SCOPES")

	if raw == "" {
		return defaultScopes
	}

	var scopes []string

	// First split on commas, then split each part on whitespace so that
	// both "openid,profile" and "openid profile" (and mixed forms) work.
	for part := range strings.SplitSeq(raw, ",") {
		for field := range strings.FieldsSeq(part) {
			if field != "" {
				scopes = append(scopes, field)
			}
		}
	}

	if len(scopes) == 0 {
		return defaultScopes
	}

	return scopes
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, name, value string) {
	secure := util.ShouldSetSecureCookie()

	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   secure,
		HttpOnly: true,
	}

	http.SetCookie(w, c)
}

func deleteCallbackCookie(w http.ResponseWriter, name string) {
	secure := util.ShouldSetSecureCookie()

	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		HttpOnly: true,
	}

	http.SetCookie(w, c)
}

func main() {
	util.SetDefaultEnvironment(config.NewEnvironmentConfig())

	ctx := context.Background()

	log.Printf("Initializing OIDC provider: %s", openIDProvider)
	provider, err := oidc.NewProvider(ctx, openIDProvider)
	if err != nil {
		log.Fatalf("Failed to query provider %q: %v", openIDProvider, err)
	}

	log.Printf("OIDC Provider endpoints: %+v", provider.Endpoint())

	var providerClaims struct {
		EndSessionEndpoint    string `json:"end_session_endpoint"`
		IntrospectionEndpoint string `json:"introspection_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	if err := provider.Claims(&providerClaims); err != nil {
		log.Printf("Warning: Failed to extract provider claims: %v", err)
	} else {
		if providerClaims.EndSessionEndpoint != "" {
			log.Printf("Logout endpoint discovered: %s", providerClaims.EndSessionEndpoint)
		}
		if providerClaims.IntrospectionEndpoint != "" {
			log.Printf("Introspection endpoint discovered: %s", providerClaims.IntrospectionEndpoint)
		}
		if providerClaims.JwksURI != "" {
			log.Printf("JWKS URI discovered: %s", providerClaims.JwksURI)
		}
	}

	tmpl, err := template.New("success").Parse(successPageTmpl)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	scopes := parseScopesFromEnv()

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:9094/oauth2",
		Scopes:       scopes,
	}

	log.Printf("Client configuration: ID=%s, RedirectURL=%s, Scopes=%v", clientID, oauth2Config.RedirectURL, oauth2Config.Scopes)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
	})

	http.HandleFunc("/oauth2", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received callback on '/oauth2'")

		queryState := r.URL.Query().Get("state")
		queryCode := r.URL.Query().Get("code")
		log.Printf("Query parameters: state=%s, code=%s", queryState, queryCode)

		stateCookie, err := r.Cookie("state")
		if err != nil {
			log.Printf("State cookie missing: %v", err)
			http.Error(w, "state not found", http.StatusBadRequest)

			return
		}
		log.Printf("Cookie state=%s", stateCookie.Value)

		if queryState != stateCookie.Value {
			log.Printf("State mismatch: query=%s, cookie=%s", queryState, stateCookie.Value)
			http.Error(w, "state did not match", http.StatusBadRequest)

			return
		}

		log.Println("Exchanging authorization code for tokens...")
		oauth2Token, err := oauth2Config.Exchange(ctx, queryCode)
		if err != nil {
			log.Printf("Token exchange failed: %v", err)
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)

			return
		}
		log.Println("Token exchange successful")

		// Per OIDC Core 1.0 §3.1.2.1: id_token is only present when "openid" scope was requested.
		// Without "openid", the server returns a pure OAuth 2.0 response (access_token only).
		hasOpenID := slices.Contains(scopes, oidc.ScopeOpenID)
		rawIDToken, _ := oauth2Token.Extra("id_token").(string)
		signatureVerified := false

		resp := struct {
			OAuth2Token         *oauth2.Token
			IDTokenClaims       *json.RawMessage `json:",omitzero"`
			IntrospectionResult *json.RawMessage `json:",omitzero"`
		}{OAuth2Token: oauth2Token}

		if hasOpenID {
			if rawIDToken == "" {
				log.Println("ID token missing in exchange response despite openid scope")
				http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)

				return
			}

			log.Printf("Raw ID Token received (length: %d)", len(rawIDToken))

			log.Println("Verifying ID Token...")

			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				log.Printf("ID Token verification failed: %v", err)
				http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)

				return
			}

			signatureVerified = true

			log.Println("ID Token verification successful")

			nonceCookie, err := r.Cookie("nonce")
			if err != nil {
				log.Printf("Nonce cookie missing: %v", err)
				http.Error(w, "nonce not found", http.StatusBadRequest)

				return
			}

			log.Printf("Cookie nonce=%s, Token nonce=%s", nonceCookie.Value, idToken.Nonce)

			if idToken.Nonce != nonceCookie.Value {
				log.Printf("Nonce mismatch: token=%s, cookie=%s", idToken.Nonce, nonceCookie.Value)
				http.Error(w, "nonce did not match", http.StatusBadRequest)

				return
			}

			log.Println("Extracting claims from ID Token...")

			idTokenClaims := new(json.RawMessage)

			if err := idToken.Claims(idTokenClaims); err != nil {
				log.Printf("Failed to extract claims: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)

				return
			}

			resp.IDTokenClaims = idTokenClaims

			log.Println("Claims extracted successfully")
		} else {
			log.Println("Pure OAuth 2.0 flow (no openid scope) - skipping ID token verification")
		}

		deleteCallbackCookie(w, "state")
		deleteCallbackCookie(w, "nonce")

		if providerClaims.IntrospectionEndpoint != "" {
			log.Printf("Performing introspection at: %s", providerClaims.IntrospectionEndpoint)
			form := url.Values{}
			form.Set("token", oauth2Token.AccessToken)
			form.Set("client_id", clientID)
			form.Set("client_secret", clientSecret)

			respIntr, err := http.PostForm(providerClaims.IntrospectionEndpoint, form)
			if err != nil {
				log.Printf("Introspection request failed: %v", err)
			} else {
				defer respIntr.Body.Close()
				if respIntr.StatusCode == http.StatusOK {
					var intr json.RawMessage
					if err := json.NewDecoder(respIntr.Body).Decode(&intr); err != nil {
						log.Printf("Failed to decode introspection response: %v", err)
					} else {
						resp.IntrospectionResult = &intr
						log.Println("Introspection successful")
					}
				} else {
					body, _ := io.ReadAll(respIntr.Body)
					log.Printf("Introspection failed with status %d: %s", respIntr.StatusCode, string(body))
				}
			}
		}

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			log.Printf("Failed to marshal response: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		log.Printf("Sending response back to browser (%d bytes)", len(data))

		jwksJSON := ""
		if providerClaims.JwksURI != "" {
			respJwks, err := http.Get(providerClaims.JwksURI)
			if err != nil {
				log.Printf("Failed to fetch JWKS: %v", err)
			} else {
				defer respJwks.Body.Close()
				body, _ := io.ReadAll(respJwks.Body)
				var prettyJWKS json.RawMessage
				if err := json.Unmarshal(body, &prettyJWKS); err == nil {
					if indent, err := json.MarshalIndent(prettyJWKS, "", "    "); err == nil {
						jwksJSON = string(indent)
					} else {
						jwksJSON = string(body)
					}
				} else {
					jwksJSON = string(body)
				}
			}
		}

		twoFAHomeURL := ""
		if u, err := url.Parse(openIDProvider); err == nil {
			u.Path = "/mfa/register/home"
			u.RawQuery = ""
			u.Fragment = ""
			twoFAHomeURL = u.String()
		}

		logoutURL := ""
		if providerClaims.EndSessionEndpoint != "" {
			u, _ := url.Parse(providerClaims.EndSessionEndpoint)
			q := u.Query()
			q.Set("id_token_hint", rawIDToken)
			q.Set("post_logout_redirect_uri", "http://127.0.0.1:9094/logout-callback")
			u.RawQuery = q.Encode()
			logoutURL = u.String()
		}

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
			LogoutURL:             logoutURL,
			TwoFAHomeURL:          twoFAHomeURL,
			SignatureVerified:     signatureVerified,
			JWKS:                  jwksJSON,
			JwksURI:               providerClaims.JwksURI,
			FrontChannelLogoutURI: "http://127.0.0.1:9094/frontchannel-logout",
			BackChannelLogoutURI:  "http://127.0.0.1:9094/backchannel-logout",
		})
		if err != nil {
			log.Printf("Failed to render template: %v", err)
		}
	})

	http.HandleFunc("/frontchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on '/frontchannel-logout'")
		iss := r.URL.Query().Get("iss")
		sid := r.URL.Query().Get("sid")
		log.Printf("Front-channel logout params: iss=%s, sid=%s", iss, sid)

		// Clear cookies (best effort)
		deleteCallbackCookie(w, "state")
		deleteCallbackCookie(w, "nonce")

		// Also clear typical session cookies if on the same domain
		cookies := []string{"token", "Nauthilus_session"}
		secure := util.ShouldSetSecureCookie()
		for _, name := range cookies {
			http.SetCookie(w, &http.Cookie{
				Name:     name,
				Value:    "",
				Path:     "/",
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				Secure:   secure,
				HttpOnly: true,
			})
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Front-channel logout processed")
	})

	http.HandleFunc("/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
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

		// Verify logout_token
		token, err := verifier.Verify(ctx, logoutToken)
		if err != nil {
			log.Printf("Failed to verify logout_token: %v", err)
			http.Error(w, "Invalid logout_token", http.StatusBadRequest)
			return
		}

		var claims struct {
			Events map[string]interface{} `json:"events"`
			Sid    string                 `json:"sid"`
			Nonce  string                 `json:"nonce"`
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
	})

	http.HandleFunc("/logout-callback", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on '/logout-callback'")

		// Clear the session cookies. "Nauthilus_session" is the default for Nauthilus IdP.
		// "token" might be set if SAML was used on the same domain.
		cookies := []string{"token", "Nauthilus_session"}
		secure := util.ShouldSetSecureCookie()

		for _, name := range cookies {
			http.SetCookie(w, &http.Cookie{
				Name:     name,
				Value:    "",
				Path:     "/",
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				Secure:   secure,
				HttpOnly: true,
			})
		}

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
	})

	log.Printf("listening on http://%s/", "127.0.0.1:9094")
	log.Fatal(http.ListenAndServe("127.0.0.1:9094", nil))
}
