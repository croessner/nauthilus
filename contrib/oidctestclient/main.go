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
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/util"
)

// initProvider initializes the OIDC provider and extracts provider metadata claims.
func initProvider(ctx context.Context) (*oidc.Provider, *ProviderClaims) {
	log.Printf("Initializing OIDC provider: %s", openIDProvider)

	provider, err := oidc.NewProvider(ctx, openIDProvider)
	if err != nil {
		log.Fatalf("Failed to query provider %q: %v", openIDProvider, err)
	}

	log.Printf("OIDC Provider endpoints: %+v", provider.Endpoint())

	providerClaims := new(ProviderClaims)

	if err := provider.Claims(providerClaims); err != nil {
		log.Printf("Warning: Failed to extract provider claims: %v", err)
	} else {
		providerClaims.logDiscoveredEndpoints()
	}

	return provider, providerClaims
}

func main() {
	util.SetDefaultEnvironment(config.NewEnvironmentConfig())

	ctx := context.Background()
	flowType := parseFlowTypeFromEnv()
	scopes := parseScopesFromEnv()

	provider, providerClaims := initProvider(ctx)

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	verifier := provider.Verifier(oidcConfig)

	log.Printf("Selected flow type: %s", flowType)

	switch flowType {
	case FlowAuthorizationCode:
		tmpl := parseSuccessTemplate()

		registerAuthorizationCodeRoutes(ctx, provider, providerClaims, verifier, tmpl, scopes)

	case FlowDeviceCode:
		// Device Code flow runs entirely on the console and terminates.
		registerDeviceCodeRoutes(ctx, provider, providerClaims, verifier, scopes)

		return

	case FlowClientCredentials:
		// Client Credentials flow runs entirely on the console and terminates.
		registerClientCredentialsRoutes(ctx, provider, providerClaims, verifier, scopes)

		return
	}

	log.Printf("listening on http://%s/", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
