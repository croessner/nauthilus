// Copyright (C) 2025 Christian Rößner
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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml/samlsp"
)

var (
	samlIDPMetadataURL = os.Getenv("SAML2_IDP_METADATA_URL")
	samlSPEntityID     = os.Getenv("SAML2_SP_ENTITY_ID")
	samlSPURL          = os.Getenv("SAML2_SP_URL")
	insecureSkipVerify = os.Getenv("SAML2_INSECURE_SKIP_VERIFY") != "false" // Default to true for test client
)

const successPageTmpl = `
<!DOCTYPE html>
<html>
<head>
    <title>SAML2 Test Client - Success</title>
    <style>
        body { font-family: sans-serif; margin: 2em; line-height: 1.5; }
        pre { background: #f4f4f4; padding: 1em; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd; }
        .container { max-width: 1000px; margin: 0 auto; }
        .back-btn { 
            display: inline-block; 
            padding: 10px 20px; 
            background-color: #5bc0de; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin-top: 20px;
            font-weight: bold;
        }
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
    </style>
</head>
<body>
    <div class="container">
        <h1>SAML2 Login Successful</h1>
        <p>The following attributes were received from the IdP:</p>
        <pre>{{.Attributes}}</pre>
        <div style="margin-top: 20px;">
            {{if .TwoFAHomeURL}}
                <a href="{{.TwoFAHomeURL}}" class="twofa-btn">Manage 2FA (TOTP/WebAuthn)</a>
            {{end}}
            <a href="/logout" class="back-btn" style="background-color: #d9534f;">Clear Session</a>
        </div>
    </div>
</body>
</html>
`

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Nauthilus SAML2 Test Client"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}

func main() {
	if samlIDPMetadataURL == "" {
		samlIDPMetadataURL = "https://localhost:9443/saml/metadata"
	}
	if samlSPEntityID == "" {
		samlSPEntityID = "https://localhost:9095/saml/metadata"
	}
	if samlSPURL == "" {
		samlSPURL = "https://localhost:9095"
	}

	var keyPair tls.Certificate
	var err error

	keyPair, err = tls.LoadX509KeyPair("contrib/saml2testclient/token.crt", "contrib/saml2testclient/token.key")
	if err != nil {
		log.Printf("Warning: Could not load keypair: %v. Generating a self-signed one...", err)
		keyPair, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("Failed to generate self-signed cert: %v", err)
		}
	}

	idpMetadataURL, err := url.Parse(samlIDPMetadataURL)
	if err != nil {
		log.Fatalf("Invalid IDP Metadata URL: %v", err)
	}

	spURL, err := url.Parse(samlSPURL)
	if err != nil {
		log.Fatalf("Invalid SP URL: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		},
	}

	opts := samlsp.Options{
		URL:               *spURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		EntityID:          samlSPEntityID,
		AllowIDPInitiated: true,
		HTTPClient:        httpClient,
	}

	// Try to fetch IDP metadata, but don't fail immediately if IdP is not up yet
	// (though samlsp.New might need it if we want it fully initialized)
	log.Printf("Fetching IdP metadata from %s...", samlIDPMetadataURL)
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), httpClient, *idpMetadataURL)
	if err != nil {
		log.Printf("Warning: Could not fetch IdP metadata: %v. The client might not work until restarted or metadata is available.", err)
	} else {
		opts.IDPMetadata = idpMetadata
	}

	samlSP, err := samlsp.New(opts)
	if err != nil {
		log.Fatalf("Failed to initialize SAML SP: %v", err)
	}

	var sloURL string
	if idpMetadata != nil {
		for _, idpSSODescriptor := range idpMetadata.IDPSSODescriptors {
			for _, endpoint := range idpSSODescriptor.SingleLogoutServices {
				if endpoint.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
					sloURL = endpoint.Location
					break
				}
			}
		}
	}

	tmpl, err := template.New("success").Parse(successPageTmpl)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	// Request logging middleware
	logRequest := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Received request: %s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)
			next.ServeHTTP(w, r)
		})
	}

	http.Handle("/saml/", logRequest(samlSP))
	http.Handle("/saml/login", logRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure that after successful login, we are redirected back to / instead of /saml/login,
		// which would cause a loop.
		r.URL.Path = "/"
		samlSP.HandleStartAuthFlow(w, r)
	})))

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// Clear the session cookies. "token" is the default for samlsp.
		// "Nauthilus_session" is the default for Nauthilus IdP.
		cookies := []string{"token", "Nauthilus_session"}

		for _, name := range cookies {
			http.SetCookie(w, &http.Cookie{
				Name:     name,
				Value:    "",
				Path:     "/",
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				HttpOnly: true,
			})
		}

		if sloURL != "" {
			http.Redirect(w, r, sloURL, http.StatusFound)

			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)
		session, err := samlSP.Session.GetSession(r)
		if session != nil && err == nil {
			// User is logged in, show attributes
			var attrs samlsp.Attributes
			if sa, ok := session.(samlsp.SessionWithAttributes); ok {
				attrs = sa.GetAttributes()
			}
			data, _ := json.MarshalIndent(attrs, "", "    ")

			twoFAHomeURL := ""
			if u, err := url.Parse(samlIDPMetadataURL); err == nil {
				u.Path = "/mfa/register/home"
				u.RawQuery = ""
				u.Fragment = ""
				twoFAHomeURL = u.String()
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl.Execute(w, struct {
				Attributes   string
				TwoFAHomeURL string
			}{
				Attributes:   string(data),
				TwoFAHomeURL: twoFAHomeURL,
			})
			return
		}

		// User not logged in, show login link
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><h1>SAML2 Test Client</h1><a href="/saml/login">Login via SAML2</a></body></html>`)
	})

	isHTTPS := spURL.Scheme == "https"

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
	}

	server := &http.Server{
		Addr:      spURL.Host,
		TLSConfig: tlsConfig,
	}

	if isHTTPS {
		log.Printf("listening on https://%s/", server.Addr)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("listening on http://%s/", server.Addr)
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}
