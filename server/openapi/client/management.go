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
	"errors"
	"net/http"

	management "github.com/croessner/nauthilus/v3/server/openapi/generated/management"
)

// ErrNilClient reports a nil generated client dependency.
var ErrNilClient = errors.New("nil generated client")

// SupportedManagementClient is the production-supported generated management
// client boundary.
type SupportedManagementClient interface {
	GetOpenAPIYAML(
		context.Context,
		...management.RequestEditorFn,
	) (*http.Response, error)
	GetOpenAPIJSON(
		context.Context,
		...management.RequestEditorFn,
	) (*management.GetOpenAPIJSONResponse, error)
	ListBruteForceEntries(
		context.Context,
		...management.RequestEditorFn,
	) (*management.ListBruteForceEntriesResponse, error)
	ListBruteForceEntriesWithParams(
		context.Context,
		*management.ListBruteForceEntriesParams,
		...management.RequestEditorFn,
	) (*management.ListBruteForceEntriesResponse, error)
	ListFilteredBruteForceEntries(
		context.Context,
		management.ListFilteredBruteForceEntriesJSONRequestBody,
		...management.RequestEditorFn,
	) (*management.ListFilteredBruteForceEntriesResponse, error)
	ListFilteredBruteForceEntriesWithParams(
		context.Context,
		*management.ListFilteredBruteForceEntriesParams,
		management.ListFilteredBruteForceEntriesJSONRequestBody,
		...management.RequestEditorFn,
	) (*management.ListFilteredBruteForceEntriesResponse, error)
	FlushBruteForceRule(
		context.Context,
		management.FlushBruteForceRuleJSONRequestBody,
		...management.RequestEditorFn,
	) (*management.FlushBruteForceRuleResponse, error)
	EnqueueBruteForceRuleFlush(
		context.Context,
		management.EnqueueBruteForceRuleFlushJSONRequestBody,
		...management.RequestEditorFn,
	) (*management.EnqueueBruteForceRuleFlushResponse, error)
	FlushUserCache(
		context.Context,
		management.FlushUserCacheJSONRequestBody,
		...management.RequestEditorFn,
	) (*management.FlushUserCacheResponse, error)
	EnqueueUserCacheFlush(
		context.Context,
		management.EnqueueUserCacheFlushJSONRequestBody,
		...management.RequestEditorFn,
	) (*management.EnqueueUserCacheFlushResponse, error)
	GetAsyncJobStatus(
		context.Context,
		string,
		...management.RequestEditorFn,
	) (*management.GetAsyncJobStatusResponse, error)
	LoadRuntimeConfig(
		context.Context,
		...management.RequestEditorFn,
	) (*management.LoadRuntimeConfigResponse, error)
	ListOIDCSessions(
		context.Context,
		string,
		...management.RequestEditorFn,
	) (*management.ListOIDCSessionsResponse, error)
	DeleteOIDCSessions(
		context.Context,
		string,
		...management.RequestEditorFn,
	) (*management.DeleteOIDCSessionsResponse, error)
	DeleteOIDCSession(
		context.Context,
		string,
		string,
		...management.RequestEditorFn,
	) (*management.DeleteOIDCSessionResponse, error)
}

type generatedManagementClient interface {
	management.ClientInterface
	management.ClientWithResponsesInterface
}

// ManagementClient wraps the supported subset of the generated management
// OpenAPI client.
type ManagementClient struct {
	generated generatedManagementClient
}

var (
	_ SupportedManagementClient = (*ManagementClient)(nil)
	_ generatedManagementClient = (*management.ClientWithResponses)(nil)
)

// NewManagementClient creates the supported generated management client with
// mandatory backchannel authentication.
func NewManagementClient(
	server string,
	auth BackchannelAuth,
	options ...management.ClientOption,
) (*ManagementClient, error) {
	authEditor, err := auth.managementRequestEditor()
	if err != nil {
		return nil, err
	}

	clientOptions := make([]management.ClientOption, 0, len(options)+1)
	clientOptions = append(clientOptions, options...)
	clientOptions = append(clientOptions, management.WithRequestEditorFn(authEditor))

	generated, err := management.NewClientWithResponses(server, clientOptions...)
	if err != nil {
		return nil, err
	}

	return NewManagementClientFromGenerated(generated)
}

// NewManagementClientFromGenerated wraps an existing generated management
// client for dependency injection.
func NewManagementClientFromGenerated(generated generatedManagementClient) (*ManagementClient, error) {
	if generated == nil {
		return nil, ErrNilClient
	}

	return &ManagementClient{generated: generated}, nil
}

// GetOpenAPIYAML downloads the management OpenAPI YAML document as a raw
// generated client response.
func (client *ManagementClient) GetOpenAPIYAML(
	ctx context.Context,
	requestEditors ...management.RequestEditorFn,
) (*http.Response, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetOpenAPIYAML(ctx, requestEditors...)
}

// GetOpenAPIJSON downloads the management OpenAPI JSON document through the
// generated client contract.
func (client *ManagementClient) GetOpenAPIJSON(
	ctx context.Context,
	requestEditors ...management.RequestEditorFn,
) (*management.GetOpenAPIJSONResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetOpenAPIJSONWithResponse(ctx, requestEditors...)
}

// ListBruteForceEntries lists brute-force entries using generated response
// types from the management OpenAPI contract.
func (client *ManagementClient) ListBruteForceEntries(
	ctx context.Context,
	requestEditors ...management.RequestEditorFn,
) (*management.ListBruteForceEntriesResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.ListBruteForceEntriesWithResponse(ctx, nil, requestEditors...)
}

// ListBruteForceEntriesWithParams lists brute-force entries with optional paging
// parameters using generated response types from the management OpenAPI contract.
func (client *ManagementClient) ListBruteForceEntriesWithParams(
	ctx context.Context,
	params *management.ListBruteForceEntriesParams,
	requestEditors ...management.RequestEditorFn,
) (*management.ListBruteForceEntriesResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.ListBruteForceEntriesWithResponse(ctx, params, requestEditors...)
}

// ListFilteredBruteForceEntries lists filtered brute-force entries using
// generated request and response types.
func (client *ManagementClient) ListFilteredBruteForceEntries(
	ctx context.Context,
	body management.ListFilteredBruteForceEntriesJSONRequestBody,
	requestEditors ...management.RequestEditorFn,
) (*management.ListFilteredBruteForceEntriesResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.ListFilteredBruteForceEntriesWithResponse(ctx, nil, body, requestEditors...)
}

// ListFilteredBruteForceEntriesWithParams lists filtered brute-force entries
// with optional paging parameters using generated request and response types.
func (client *ManagementClient) ListFilteredBruteForceEntriesWithParams(
	ctx context.Context,
	params *management.ListFilteredBruteForceEntriesParams,
	body management.ListFilteredBruteForceEntriesJSONRequestBody,
	requestEditors ...management.RequestEditorFn,
) (*management.ListFilteredBruteForceEntriesResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.ListFilteredBruteForceEntriesWithResponse(ctx, params, body, requestEditors...)
}

// FlushBruteForceRule flushes one brute-force rule using generated request and
// response types.
func (client *ManagementClient) FlushBruteForceRule(
	ctx context.Context,
	body management.FlushBruteForceRuleJSONRequestBody,
	requestEditors ...management.RequestEditorFn,
) (*management.FlushBruteForceRuleResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.FlushBruteForceRuleWithResponse(ctx, body, requestEditors...)
}

// EnqueueBruteForceRuleFlush enqueues a brute-force rule flush using generated
// request and response types.
func (client *ManagementClient) EnqueueBruteForceRuleFlush(
	ctx context.Context,
	body management.EnqueueBruteForceRuleFlushJSONRequestBody,
	requestEditors ...management.RequestEditorFn,
) (*management.EnqueueBruteForceRuleFlushResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.EnqueueBruteForceRuleFlushWithResponse(ctx, body, requestEditors...)
}

// FlushUserCache flushes the user cache synchronously using generated request
// and response types.
func (client *ManagementClient) FlushUserCache(
	ctx context.Context,
	body management.FlushUserCacheJSONRequestBody,
	requestEditors ...management.RequestEditorFn,
) (*management.FlushUserCacheResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.FlushUserCacheWithResponse(ctx, body, requestEditors...)
}

// EnqueueUserCacheFlush enqueues the supported cache flush operation using the
// generated request and response types from the management OpenAPI contract.
func (client *ManagementClient) EnqueueUserCacheFlush(
	ctx context.Context,
	body management.EnqueueUserCacheFlushJSONRequestBody,
	requestEditors ...management.RequestEditorFn,
) (*management.EnqueueUserCacheFlushResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.EnqueueUserCacheFlushWithResponse(ctx, body, requestEditors...)
}

// GetAsyncJobStatus reads an asynchronous backchannel job status using the
// generated response types from the management OpenAPI contract.
func (client *ManagementClient) GetAsyncJobStatus(
	ctx context.Context,
	jobID string,
	requestEditors ...management.RequestEditorFn,
) (*management.GetAsyncJobStatusResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetAsyncJobStatusWithResponse(ctx, jobID, requestEditors...)
}

// LoadRuntimeConfig loads the current runtime configuration through the
// generated management contract.
func (client *ManagementClient) LoadRuntimeConfig(
	ctx context.Context,
	requestEditors ...management.RequestEditorFn,
) (*management.LoadRuntimeConfigResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.LoadRuntimeConfigWithResponse(ctx, requestEditors...)
}

// ListOIDCSessions lists OIDC sessions for one user through the generated
// management contract.
func (client *ManagementClient) ListOIDCSessions(
	ctx context.Context,
	userID string,
	requestEditors ...management.RequestEditorFn,
) (*management.ListOIDCSessionsResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.ListOIDCSessionsWithResponse(ctx, userID, requestEditors...)
}

// DeleteOIDCSessions deletes all OIDC sessions for one user through the
// generated management contract.
func (client *ManagementClient) DeleteOIDCSessions(
	ctx context.Context,
	userID string,
	requestEditors ...management.RequestEditorFn,
) (*management.DeleteOIDCSessionsResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.DeleteOIDCSessionsWithResponse(ctx, userID, requestEditors...)
}

// DeleteOIDCSession deletes one OIDC session through the generated management
// contract.
func (client *ManagementClient) DeleteOIDCSession(
	ctx context.Context,
	userID string,
	token string,
	requestEditors ...management.RequestEditorFn,
) (*management.DeleteOIDCSessionResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.DeleteOIDCSessionWithResponse(ctx, userID, token, requestEditors...)
}

func (client *ManagementClient) generatedClient() (generatedManagementClient, error) {
	if client == nil || client.generated == nil {
		return nil, ErrNilClient
	}

	return client.generated, nil
}
