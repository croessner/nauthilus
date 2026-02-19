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
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/croessner/nauthilus/server/util"
)

// FlowType represents the OAuth 2.0 / OIDC grant type to execute.
type FlowType string

const (
	// FlowAuthorizationCode is the standard Authorization Code Grant flow.
	FlowAuthorizationCode FlowType = "authorization_code"

	// FlowDeviceCode is the Device Authorization Grant flow (RFC 8628).
	FlowDeviceCode FlowType = "device_code"

	// FlowClientCredentials is the Client Credentials Grant flow.
	FlowClientCredentials FlowType = "client_credentials"

	// listenAddr is the default address the test client listens on.
	listenAddr = "127.0.0.1:9094"
)

// defaultScopes defines the default OIDC scopes used when the OAUTH2_SCOPES environment variable is not set.
var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline", "offline_access", "nauthilus:mfa:manage"}

var (
	openIDProvider = os.Getenv("OPENID_PROVIDER")
	clientID       = os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret   = os.Getenv("OAUTH2_CLIENT_SECRET")
)

// ProviderClaims holds selected endpoints discovered from the OIDC provider metadata.
type ProviderClaims struct {
	EndSessionEndpoint          string `json:"end_session_endpoint"`
	IntrospectionEndpoint       string `json:"introspection_endpoint"`
	JwksURI                     string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

// logDiscoveredEndpoints logs all non-empty endpoints from the provider metadata.
func (pc *ProviderClaims) logDiscoveredEndpoints() {
	if pc.EndSessionEndpoint != "" {
		log.Printf("Logout endpoint discovered: %s", pc.EndSessionEndpoint)
	}

	if pc.IntrospectionEndpoint != "" {
		log.Printf("Introspection endpoint discovered: %s", pc.IntrospectionEndpoint)
	}

	if pc.JwksURI != "" {
		log.Printf("JWKS URI discovered: %s", pc.JwksURI)
	}

	if pc.DeviceAuthorizationEndpoint != "" {
		log.Printf("Device authorization endpoint discovered: %s", pc.DeviceAuthorizationEndpoint)
	}

	if pc.UserinfoEndpoint != "" {
		log.Printf("Userinfo endpoint discovered: %s", pc.UserinfoEndpoint)
	}

	if pc.TokenEndpoint != "" {
		log.Printf("Token endpoint discovered: %s", pc.TokenEndpoint)
	}
}

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

// parseFlowTypeFromEnv reads the OAUTH2_FLOW environment variable and returns
// the selected FlowType. Valid values are "authorization_code" (default),
// "device_code", and "client_credentials".
func parseFlowTypeFromEnv() FlowType {
	raw := strings.TrimSpace(os.Getenv("OAUTH2_FLOW"))

	switch FlowType(raw) {
	case FlowDeviceCode:
		return FlowDeviceCode
	case FlowClientCredentials:
		return FlowClientCredentials
	case FlowAuthorizationCode:
		return FlowAuthorizationCode
	default:
		if raw != "" {
			log.Printf("Warning: unknown OAUTH2_FLOW %q, falling back to %s", raw, FlowAuthorizationCode)
		}

		return FlowAuthorizationCode
	}
}

// randString generates a cryptographically random URL-safe base64 string.
func randString(nByte int) (string, error) {
	b := make([]byte, nByte)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setCallbackCookie sets a short-lived HTTP cookie used during the OIDC callback.
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

// deleteCallbackCookie removes an HTTP cookie by setting its max age to -1.
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

// clearSessionCookies removes common session cookies (e.g. after logout).
func clearSessionCookies(w http.ResponseWriter) {
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
}

// fetchJWKS retrieves and pretty-prints the JSON Web Key Set from the given URI.
func fetchJWKS(jwksURI string) string {
	if jwksURI == "" {
		return ""
	}

	resp, err := http.Get(jwksURI)
	if err != nil {
		log.Printf("Failed to fetch JWKS: %v", err)

		return ""
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var raw json.RawMessage

	if err := json.Unmarshal(body, &raw); err == nil {
		if indent, err := json.MarshalIndent(raw, "", "    "); err == nil {
			return string(indent)
		}
	}

	return string(body)
}

// build2FAHomeURL constructs the MFA registration URL from the provider issuer.
func build2FAHomeURL() string {
	u, err := url.Parse(openIDProvider)
	if err != nil {
		return ""
	}

	u.Path = "/mfa/register/home"
	u.RawQuery = ""
	u.Fragment = ""

	return u.String()
}

// buildLogoutURL constructs the end-session URL with the given ID token hint.
func buildLogoutURL(endSessionEndpoint, rawIDToken string) string {
	if endSessionEndpoint == "" {
		return ""
	}

	u, _ := url.Parse(endSessionEndpoint)

	q := u.Query()
	q.Set("id_token_hint", rawIDToken)
	q.Set("post_logout_redirect_uri", fmt.Sprintf("http://%s/logout-callback", listenAddr))
	u.RawQuery = q.Encode()

	return u.String()
}

// parseSuccessTemplate parses and returns the success page HTML template.
func parseSuccessTemplate() *template.Template {
	tmpl, err := template.New("success").Parse(successPageTmpl)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	return tmpl
}

// performIntrospection calls the introspection endpoint and returns the result as raw JSON.
func performIntrospection(introspectionEndpoint, accessToken string) *json.RawMessage {
	if introspectionEndpoint == "" {
		return nil
	}

	log.Printf("Performing introspection at: %s", introspectionEndpoint)

	form := url.Values{}
	form.Set("token", accessToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	resp, err := http.PostForm(introspectionEndpoint, form)
	if err != nil {
		log.Printf("Introspection request failed: %v", err)

		return nil
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Introspection failed with status %d: %s", resp.StatusCode, string(body))

		return nil
	}

	var intr json.RawMessage

	if err := json.NewDecoder(resp.Body).Decode(&intr); err != nil {
		log.Printf("Failed to decode introspection response: %v", err)

		return nil
	}

	log.Println("Introspection successful")

	return &intr
}

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
