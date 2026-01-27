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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"fmt"
	"html/template"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

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
        body { font-family: sans-serif; margin: 2em; line-height: 1.5; }
        pre { background: #f4f4f4; padding: 1em; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd; }
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
        .container { max-width: 1000px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Successful</h1>
        <p>The following tokens and claims were received from the provider:</p>
        <pre>{{.JSON}}</pre>
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

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}

	http.SetCookie(w, c)
}

func deleteCallbackCookie(w http.ResponseWriter, name string) {
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	http.SetCookie(w, c)
}

func main() {
	ctx := context.Background()

	log.Printf("Initializing OIDC provider: %s", openIDProvider)
	provider, err := oidc.NewProvider(ctx, openIDProvider)
	if err != nil {
		log.Fatalf("Failed to query provider %q: %v", openIDProvider, err)
	}

	log.Printf("OIDC Provider endpoints: %+v", provider.Endpoint())

	var providerClaims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&providerClaims); err != nil {
		log.Printf("Warning: Failed to extract provider claims: %v", err)
	} else if providerClaims.EndSessionEndpoint != "" {
		log.Printf("Logout endpoint discovered: %s", providerClaims.EndSessionEndpoint)
	}

	tmpl, err := template.New("success").Parse(successPageTmpl)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:9094/oauth2",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups", "dovecot", "offline", "offline_access"},
	}

	log.Printf("Client configuration: ID=%s, RedirectURL=%s, Scopes=%v", clientID, config.RedirectURL, config.Scopes)

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

		setCallbackCookie(w, r, "state", state)
		setCallbackCookie(w, r, "nonce", nonce)

		authURL := config.AuthCodeURL(state, oidc.Nonce(nonce))
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
		oauth2Token, err := config.Exchange(ctx, queryCode)
		if err != nil {
			log.Printf("Token exchange failed: %v", err)
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)

			return
		}
		log.Println("Token exchange successful")

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Println("ID token missing in exchange response")
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

		deleteCallbackCookie(w, "state")
		deleteCallbackCookie(w, "nonce")

		log.Println("Extracting claims from ID Token...")
		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			log.Printf("Failed to extract claims: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
		log.Println("Claims extracted successfully")

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			log.Printf("Failed to marshal response: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		log.Printf("Sending response back to browser (%d bytes)", len(data))

		twoFAHomeURL := ""
		if u, err := url.Parse(openIDProvider); err == nil {
			u.Path = "/2fa/v1/register/home"
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
			JSON         string
			LogoutURL    string
			TwoFAHomeURL string
		}{
			JSON:         string(data),
			LogoutURL:    logoutURL,
			TwoFAHomeURL: twoFAHomeURL,
		})
		if err != nil {
			log.Printf("Failed to render template: %v", err)
		}
	})

	http.HandleFunc("/logout-callback", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request on '/logout-callback'")
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
