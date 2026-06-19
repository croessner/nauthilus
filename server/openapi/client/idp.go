// Copyright (C) 2026 Christian Roessner
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

package client

import (
	"context"
	"net/http"

	generatedidp "github.com/croessner/nauthilus/v3/server/openapi/generated/idp"
)

// SupportedIDPDiscoveryClient is the production-supported generated IDP
// discovery client boundary.
type SupportedIDPDiscoveryClient interface {
	GetPublicOpenAPIJSON(context.Context, ...generatedidp.RequestEditorFn) (*generatedidp.GetPublicIdPOpenAPIJSONResponse, error)
	GetPublicOpenAPIYAML(context.Context, ...generatedidp.RequestEditorFn) (*http.Response, error)
	GetOIDCDiscovery(context.Context, ...generatedidp.RequestEditorFn) (*generatedidp.GetOIDCDiscoveryResponse, error)
	GetOIDCJWKS(context.Context, ...generatedidp.RequestEditorFn) (*generatedidp.GetOIDCJWKSResponse, error)
	GetSAMLMetadata(context.Context, ...generatedidp.RequestEditorFn) (*http.Response, error)
}

type generatedIDPClient interface {
	generatedidp.ClientInterface
	generatedidp.ClientWithResponsesInterface
}

// IDPDiscoveryClient wraps the supported public discovery subset of the
// generated IDP OpenAPI client.
type IDPDiscoveryClient struct {
	generated generatedIDPClient
}

var (
	_ SupportedIDPDiscoveryClient = (*IDPDiscoveryClient)(nil)
	_ generatedIDPClient          = (*generatedidp.ClientWithResponses)(nil)
)

// NewIDPDiscoveryClient creates the supported generated IDP discovery client.
func NewIDPDiscoveryClient(server string, options ...generatedidp.ClientOption) (*IDPDiscoveryClient, error) {
	generated, err := generatedidp.NewClientWithResponses(server, options...)
	if err != nil {
		return nil, err
	}

	return NewIDPDiscoveryClientFromGenerated(generated)
}

// NewIDPDiscoveryClientFromGenerated wraps an existing generated IDP client for
// dependency injection.
func NewIDPDiscoveryClientFromGenerated(generated generatedIDPClient) (*IDPDiscoveryClient, error) {
	if generated == nil {
		return nil, ErrNilClient
	}

	return &IDPDiscoveryClient{generated: generated}, nil
}

// GetPublicOpenAPIJSON downloads the public IDP OpenAPI JSON document through
// the generated client contract.
func (client *IDPDiscoveryClient) GetPublicOpenAPIJSON(
	ctx context.Context,
	requestEditors ...generatedidp.RequestEditorFn,
) (*generatedidp.GetPublicIdPOpenAPIJSONResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetPublicIdPOpenAPIJSONWithResponse(ctx, requestEditors...)
}

// GetPublicOpenAPIYAML downloads the public IDP OpenAPI YAML document as a raw
// generated client response.
func (client *IDPDiscoveryClient) GetPublicOpenAPIYAML(
	ctx context.Context,
	requestEditors ...generatedidp.RequestEditorFn,
) (*http.Response, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetPublicIdPOpenAPIYAML(ctx, requestEditors...)
}

// GetOIDCDiscovery downloads OIDC discovery metadata through the generated
// client contract.
func (client *IDPDiscoveryClient) GetOIDCDiscovery(
	ctx context.Context,
	requestEditors ...generatedidp.RequestEditorFn,
) (*generatedidp.GetOIDCDiscoveryResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetOIDCDiscoveryWithResponse(ctx, requestEditors...)
}

// GetOIDCJWKS downloads the OIDC JWKS through the generated client contract.
func (client *IDPDiscoveryClient) GetOIDCJWKS(
	ctx context.Context,
	requestEditors ...generatedidp.RequestEditorFn,
) (*generatedidp.GetOIDCJWKSResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetOIDCJWKSWithResponse(ctx, requestEditors...)
}

// GetSAMLMetadata downloads SAML metadata as a raw generated client response.
func (client *IDPDiscoveryClient) GetSAMLMetadata(
	ctx context.Context,
	requestEditors ...generatedidp.RequestEditorFn,
) (*http.Response, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetSAMLMetadata(ctx, requestEditors...)
}

func (client *IDPDiscoveryClient) generatedClient() (generatedIDPClient, error) {
	if client == nil || client.generated == nil {
		return nil, ErrNilClient
	}

	return client.generated, nil
}
