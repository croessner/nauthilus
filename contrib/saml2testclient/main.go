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
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/util"
	dsig "github.com/russellhaering/goxmldsig"
)

var (
	samlIDPMetadataURL  = os.Getenv("SAML2_IDP_METADATA_URL")
	samlSPEntityID      = os.Getenv("SAML2_SP_ENTITY_ID")
	samlSPURL           = os.Getenv("SAML2_SP_URL")
	insecureSkipVerify  = os.Getenv("SAML2_INSECURE_SKIP_VERIFY") != "false" // Default to true for test client
	signAuthnRequests   = envBool("SAML2_SP_SIGN_AUTHN_REQUESTS", false)
	signLogoutRequests  = envBool("SAML2_SP_SIGN_LOGOUT_REQUESTS", false)
	signLogoutResponses = envBool("SAML2_SP_SIGN_LOGOUT_RESPONSES", false)
)

const sessionIndexAttribute = "SessionIndex"

type logoutInitiation struct {
	Binding     string
	RedirectURL *url.URL
	PostBody    []byte
}

type incomingSLOMessage struct {
	MessageType string
	Binding     string
	Payload     string
	RelayState  string
}

const successPageTmpl = `
<!DOCTYPE html>
<html>
<head>
    <title>SAML2 Test Client - Success</title>
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

        <div class="section">
            <h2>Authentication</h2>
            <span class="status-badge status-success">✓ SAML2 Authentication Successful</span>
        </div>

        <div class="section">
            <h2>SAML Attributes</h2>
            <p>The following attributes were received from the IdP:</p>
            <pre>{{.Attributes}}</pre>
        </div>

        <div style="margin-top: 20px;">
            {{if .TwoFAHomeURL}}
                <a href="{{.TwoFAHomeURL}}" class="twofa-btn">Manage 2FA (TOTP/WebAuthn)</a>
            {{end}}
            <a href="/logout" class="logout-btn">Logout</a>
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

	certificate := x509.Certificate{
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &certificate, &certificate, &priv.PublicKey, priv)
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

// exportSPCertificate writes the SP certificate as PEM to a well-known file
// so it can be referenced via the IdP's cert_file configuration option.
func exportSPCertificate(keyPair tls.Certificate) {
	const certPath = "contrib/saml2testclient/sp-cert.pem"

	if len(keyPair.Certificate) == 0 {
		log.Printf("Warning: No certificate to export")

		return
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: keyPair.Certificate[0],
	}

	pemData := pem.EncodeToMemory(pemBlock)

	if err := os.WriteFile(certPath, pemData, 0o644); err != nil {
		log.Printf("Warning: Could not export SP certificate to %s: %v", certPath, err)

		return
	}

	log.Printf("SP certificate exported to %s (use this in IdP saml2.service_providers[].cert_file)", certPath)
}

func envBool(key string, defaultValue bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}

	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		log.Printf("Warning: Invalid boolean value %q for %s. Using default %t.", value, key, defaultValue)

		return defaultValue
	}
}

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

func sessionLogoutContext(middleware *samlsp.Middleware, r *http.Request) (string, string, error) {
	if middleware == nil {
		return "", "", fmt.Errorf("saml middleware is not initialized")
	}

	session, err := middleware.Session.GetSession(r)
	if err != nil {
		return "", "", err
	}

	claims, ok := session.(samlsp.JWTSessionClaims)
	if !ok {
		return "", "", fmt.Errorf("unsupported session type %T", session)
	}

	nameID := strings.TrimSpace(claims.Subject)
	if nameID == "" {
		return "", "", fmt.Errorf("session NameID is missing")
	}

	sessionIndex := strings.TrimSpace(claims.Attributes.Get(sessionIndexAttribute))

	return nameID, sessionIndex, nil
}

func buildLogoutInitiation(
	serviceProvider *saml.ServiceProvider,
	binding, nameID, sessionIndex, relayState string,
	signRequest bool,
) (*logoutInitiation, error) {
	if serviceProvider == nil {
		return nil, fmt.Errorf("service provider is not initialized")
	}

	logoutRequest, err := newLogoutRequest(serviceProvider, binding, nameID, sessionIndex, signRequest)
	if err != nil {
		return nil, err
	}

	initiation := &logoutInitiation{Binding: binding}

	switch binding {
	case saml.HTTPRedirectBinding:
		if signRequest {
			redirectURL, err := buildSignedRedirectLogoutRequestURL(logoutRequest, relayState, serviceProvider)
			if err != nil {
				return nil, err
			}

			initiation.RedirectURL = redirectURL
		} else {
			initiation.RedirectURL = logoutRequest.Redirect(relayState)
		}
	case saml.HTTPPostBinding:
		initiation.PostBody = logoutRequest.Post(relayState)
	default:
		return nil, fmt.Errorf("unsupported logout binding %q", binding)
	}

	return initiation, nil
}

func newLogoutRequest(
	serviceProvider *saml.ServiceProvider,
	binding, nameID, sessionIndex string,
	signRequest bool,
) (*saml.LogoutRequest, error) {
	logoutDestination := strings.TrimSpace(serviceProvider.GetSLOBindingLocation(binding))
	if logoutDestination == "" {
		return nil, fmt.Errorf("missing IdP SingleLogoutService for binding %q", binding)
	}

	signingServiceProvider, err := cloneServiceProviderForSigning(serviceProvider, signRequest)
	if err != nil {
		return nil, err
	}

	logoutRequest, err := signingServiceProvider.MakeLogoutRequest(logoutDestination, nameID)
	if err != nil {
		return nil, err
	}

	if sessionIndex != "" {
		logoutRequest.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}

	// Redirect binding signatures are transported via the query string, not embedded XML.
	if binding == saml.HTTPRedirectBinding {
		logoutRequest.Signature = nil
	}

	return logoutRequest, nil
}

func buildSignedRedirectLogoutRequestURL(
	logoutRequest *saml.LogoutRequest,
	relayState string,
	serviceProvider *saml.ServiceProvider,
) (*url.URL, error) {
	if logoutRequest == nil {
		return nil, fmt.Errorf("logout request is missing")
	}

	signingServiceProvider, err := cloneServiceProviderForSigning(serviceProvider, true)
	if err != nil {
		return nil, err
	}

	deflated, err := logoutRequest.Deflate()
	if err != nil {
		return nil, err
	}

	rawSAMLRequest := url.QueryEscape(base64.StdEncoding.EncodeToString(deflated))
	rawSigAlg := url.QueryEscape(signingServiceProvider.SignatureMethod)

	signedContent := "SAMLRequest=" + rawSAMLRequest
	if relayState != "" {
		signedContent += "&RelayState=" + url.QueryEscape(relayState)
	}

	signedContent += "&SigAlg=" + rawSigAlg

	signingContext, err := saml.GetSigningContext(signingServiceProvider)
	if err != nil {
		return nil, err
	}

	signature, err := signingContext.SignString(signedContent)
	if err != nil {
		return nil, err
	}

	redirectURL, err := url.Parse(logoutRequest.Destination)
	if err != nil {
		return nil, err
	}

	redirectURL.RawQuery = signedContent + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))

	return redirectURL, nil
}

func cloneServiceProviderForSigning(serviceProvider *saml.ServiceProvider, signMessages bool) (*saml.ServiceProvider, error) {
	if serviceProvider == nil {
		return nil, fmt.Errorf("service provider is not initialized")
	}

	clone := *serviceProvider
	if !signMessages {
		clone.SignatureMethod = ""

		return &clone, nil
	}

	if clone.SignatureMethod != "" {
		return &clone, nil
	}

	signatureMethod, err := defaultSignatureMethodForKey(clone.Key)
	if err != nil {
		return nil, err
	}

	clone.SignatureMethod = signatureMethod

	return &clone, nil
}

func defaultSignatureMethodForKey(key crypto.PrivateKey) (string, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return dsig.RSASHA256SignatureMethod, nil
	case *ecdsa.PrivateKey:
		return dsig.ECDSASHA256SignatureMethod, nil
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}

func preferredLogoutBinding(serviceProvider *saml.ServiceProvider) string {
	if serviceProvider == nil {
		return ""
	}

	if binding := strings.TrimSpace(serviceProvider.GetSLOBindingLocation(saml.HTTPRedirectBinding)); binding != "" {
		return saml.HTTPRedirectBinding
	}

	if binding := strings.TrimSpace(serviceProvider.GetSLOBindingLocation(saml.HTTPPostBinding)); binding != "" {
		return saml.HTTPPostBinding
	}

	return ""
}

func parseIncomingSLOMessage(r *http.Request) (*incomingSLOMessage, error) {
	if r == nil {
		return nil, fmt.Errorf("request is missing")
	}

	switch r.Method {
	case http.MethodGet:
		return parseIncomingSLOValues(r.URL.Query(), saml.HTTPRedirectBinding)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("cannot parse form payload: %w", err)
		}

		return parseIncomingSLOValues(r.PostForm, saml.HTTPPostBinding)
	default:
		return nil, fmt.Errorf("unsupported method %s", r.Method)
	}
}

func parseIncomingSLOValues(values url.Values, binding string) (*incomingSLOMessage, error) {
	requestPayload := strings.TrimSpace(values.Get("SAMLRequest"))
	responsePayload := strings.TrimSpace(values.Get("SAMLResponse"))
	relayState := strings.TrimSpace(values.Get("RelayState"))

	switch {
	case requestPayload != "" && responsePayload != "":
		return nil, fmt.Errorf("SAMLRequest and SAMLResponse must not be present together")
	case requestPayload != "":
		return &incomingSLOMessage{
			MessageType: "request",
			Binding:     binding,
			Payload:     requestPayload,
			RelayState:  relayState,
		}, nil
	case responsePayload != "":
		return &incomingSLOMessage{
			MessageType: "response",
			Binding:     binding,
			Payload:     responsePayload,
			RelayState:  relayState,
		}, nil
	default:
		return nil, fmt.Errorf("missing SAMLRequest/SAMLResponse payload")
	}
}

func decodeIncomingLogoutRequest(binding, payload string) (*saml.LogoutRequest, error) {
	xmlPayload, err := decodeIncomingSLOPayload(binding, payload)
	if err != nil {
		return nil, err
	}

	var logoutRequest saml.LogoutRequest

	if err = xml.Unmarshal(xmlPayload, &logoutRequest); err != nil {
		return nil, fmt.Errorf("cannot parse LogoutRequest XML: %w", err)
	}

	return &logoutRequest, nil
}

func decodeIncomingLogoutResponse(binding, payload string) ([]byte, *saml.LogoutResponse, error) {
	xmlPayload, err := decodeIncomingSLOPayload(binding, payload)
	if err != nil {
		return nil, nil, err
	}

	var logoutResponse saml.LogoutResponse

	if err = xml.Unmarshal(xmlPayload, &logoutResponse); err != nil {
		return nil, nil, fmt.Errorf("cannot parse LogoutResponse XML: %w", err)
	}

	return xmlPayload, &logoutResponse, nil
}

func decodeIncomingSLOPayload(binding, payload string) ([]byte, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, fmt.Errorf("SAML payload is empty")
	}

	rawPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("cannot decode SAML payload: %w", err)
	}

	var xmlPayload []byte

	switch binding {
	case saml.HTTPRedirectBinding:
		reader := flate.NewReader(bytes.NewReader(rawPayload))
		defer func() {
			if closeErr := reader.Close(); closeErr != nil {
				log.Printf("Warning: Failed to close flate reader: %v", closeErr)
			}
		}()

		xmlPayload, err = io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("cannot inflate SAMLRequest payload: %w", err)
		}
	case saml.HTTPPostBinding:
		xmlPayload = rawPayload
	default:
		return nil, fmt.Errorf("unsupported logout binding %q", binding)
	}

	return xmlPayload, nil
}

func xmlPayloadHasSignature(document []byte) bool {
	return bytes.Contains(document, []byte("<ds:Signature")) || bytes.Contains(document, []byte(":Signature"))
}

func validateIncomingLogoutResponse(
	serviceProvider *saml.ServiceProvider,
	r *http.Request,
	message *incomingSLOMessage,
) error {
	if serviceProvider == nil {
		return fmt.Errorf("service provider is not initialized")
	}

	responseXML, logoutResponse, err := decodeIncomingLogoutResponse(message.Binding, message.Payload)
	if err != nil {
		return err
	}

	if xmlPayloadHasSignature(responseXML) {
		if err = serviceProvider.ValidateLogoutResponseRequest(r); err != nil {
			return err
		}
	}

	if strings.TrimSpace(logoutResponse.Destination) != serviceProvider.SloURL.String() {
		return fmt.Errorf("LogoutResponse destination %q does not match %q", logoutResponse.Destination, serviceProvider.SloURL.String())
	}

	if strings.TrimSpace(logoutResponse.InResponseTo) == "" {
		return fmt.Errorf("LogoutResponse InResponseTo is missing")
	}

	if strings.TrimSpace(logoutResponse.Status.StatusCode.Value) == "" {
		return fmt.Errorf("LogoutResponse status is missing")
	}

	return nil
}

func writeSAMLPostBinding(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if _, err := w.Write(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	util.SetDefaultEnvironment(config.NewEnvironmentConfig())

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

	// Export SP certificate as PEM so it can be used in IdP configuration
	// (e.g. saml2.service_providers[].cert_file).
	exportSPCertificate(keyPair)

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
		SignRequest:       signAuthnRequests,
		LogoutBindings:    []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding},
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
	http.Handle("/saml/slo", logRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message, err := parseIncomingSLOMessage(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		switch message.MessageType {
		case "response":
			if err = validateIncomingLogoutResponse(&samlSP.ServiceProvider, r, message); err != nil {
				http.Error(w, fmt.Sprintf("invalid logout response: %v", err), http.StatusBadRequest)

				return
			}

			clearSessionCookies(w)
			http.Redirect(w, r, "/", http.StatusFound)
		case "request":
			logoutRequest, err := decodeIncomingLogoutRequest(message.Binding, message.Payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}

			signingSP, err := cloneServiceProviderForSigning(&samlSP.ServiceProvider, signLogoutResponses)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)

				return
			}

			clearSessionCookies(w)

			switch message.Binding {
			case saml.HTTPRedirectBinding:
				redirectURL, err := signingSP.MakeRedirectLogoutResponse(logoutRequest.ID, message.RelayState)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)

					return
				}

				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			case saml.HTTPPostBinding:
				postBody, err := signingSP.MakePostLogoutResponse(logoutRequest.ID, message.RelayState)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)

					return
				}

				writeSAMLPostBinding(w, postBody)
			default:
				http.Error(w, fmt.Sprintf("unsupported logout binding %q", message.Binding), http.StatusBadRequest)
			}
		default:
			http.Error(w, fmt.Sprintf("unsupported SLO message type %q", message.MessageType), http.StatusBadRequest)
		}
	})))

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		nameID, sessionIndex, err := sessionLogoutContext(samlSP, r)
		if err != nil {
			clearSessionCookies(w)
			http.Redirect(w, r, "/", http.StatusFound)

			return
		}

		binding := preferredLogoutBinding(&samlSP.ServiceProvider)
		if binding == "" {
			clearSessionCookies(w)
			http.Redirect(w, r, "/", http.StatusFound)

			return
		}

		initiation, err := buildLogoutInitiation(
			&samlSP.ServiceProvider,
			binding,
			nameID,
			sessionIndex,
			"logout",
			signLogoutRequests,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		switch initiation.Binding {
		case saml.HTTPRedirectBinding:
			http.Redirect(w, r, initiation.RedirectURL.String(), http.StatusFound)
		case saml.HTTPPostBinding:
			writeSAMLPostBinding(w, initiation.PostBody)
		default:
			http.Error(w, fmt.Sprintf("unsupported logout binding %q", initiation.Binding), http.StatusInternalServerError)
		}
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

		// User not logged in, show login page
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>SAML2 Test Client</title>
    <style>
        body { font-family: sans-serif; margin: 2em; line-height: 1.5; background-color: #f9f9f9; }
        .container { max-width: 600px; margin: 80px auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #333; }
        p { color: #666; }
        .login-btn {
            display: inline-block;
            padding: 12px 30px;
            background-color: #337ab7;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
            font-weight: bold;
            font-size: 1.1em;
        }
        .login-btn:hover { background-color: #286090; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SAML2 Test Client</h1>
        <p>Click the button below to authenticate via SAML 2.0.</p>
        <a href="/saml/login" class="login-btn">Login via SAML2</a>
    </div>
</body>
</html>`)
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
