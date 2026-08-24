// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package client

import (
	"context"
	"errors"
	"net/http"

	management "github.com/croessner/nauthilus/v3/server/openapi/generated/management"
)

// ErrInvalidPolicyAuth reports incomplete dedicated Policy client credentials.
var ErrInvalidPolicyAuth = errors.New("invalid policy auth")

// PolicyAuth is private-material Policy authentication and cannot be used as BackchannelAuth.
type PolicyAuth struct {
	token    string
	username string
	password string
	scheme   string
}

// PolicyBearerToken configures a dedicated Policy-resource Bearer credential.
func PolicyBearerToken(token string) PolicyAuth {
	return PolicyAuth{scheme: bearerAuthScheme, token: token}
}

// PolicyBasicCredentials configures dedicated Policy-Basic credentials.
func PolicyBasicCredentials(username string, password string) PolicyAuth {
	return PolicyAuth{scheme: basicAuthScheme, username: username, password: password}
}

// policyRequestEditor writes only a dedicated Policy Authorization presentation.
func (auth PolicyAuth) policyRequestEditor() (management.RequestEditorFn, error) {
	header, err := auth.authorizationHeader()
	if err != nil {
		return nil, err
	}

	return func(_ context.Context, request *http.Request) error {
		request.Header.Set(authorizationHeader, header)

		return nil
	}, nil
}

// authorizationHeader validates one Policy credential representation.
func (auth PolicyAuth) authorizationHeader() (string, error) {
	return clientAuthorizationHeader(auth.scheme, auth.token, auth.username, auth.password, ErrInvalidPolicyAuth)
}

// SupportedPolicyClient is the dedicated supported unary Policy API surface.
type SupportedPolicyClient interface {
	Evaluate(context.Context, management.EvaluatePolicyDecisionJSONRequestBody, ...management.RequestEditorFn) (*management.EvaluatePolicyDecisionResponse, error)
}

type generatedPolicyClient interface {
	EvaluatePolicyDecisionWithResponse(context.Context, management.EvaluatePolicyDecisionJSONRequestBody, ...management.RequestEditorFn) (*management.EvaluatePolicyDecisionResponse, error)
}

// PolicyClient wraps the generated client without exposing management authentication types.
type PolicyClient struct {
	generated generatedPolicyClient
}

var _ SupportedPolicyClient = (*PolicyClient)(nil)

// NewPolicyClient creates the supported Policy-only generated client.
func NewPolicyClient(server string, auth PolicyAuth, options ...management.ClientOption) (*PolicyClient, error) {
	editor, err := auth.policyRequestEditor()
	if err != nil {
		return nil, err
	}

	options = append(options, management.WithRequestEditorFn(editor))

	generated, err := management.NewClientWithResponses(server, options...)
	if err != nil {
		return nil, err
	}

	return NewPolicyClientFromGenerated(generated)
}

// NewPolicyClientFromGenerated wraps a generated Policy operation seam for dependency injection.
func NewPolicyClientFromGenerated(generated generatedPolicyClient) (*PolicyClient, error) {
	if generated == nil {
		return nil, ErrNilClient
	}

	return &PolicyClient{generated: generated}, nil
}

// Evaluate performs exactly one generated Policy decision operation.
func (client *PolicyClient) Evaluate(ctx context.Context, body management.EvaluatePolicyDecisionJSONRequestBody, editors ...management.RequestEditorFn) (*management.EvaluatePolicyDecisionResponse, error) {
	if client == nil || client.generated == nil {
		return nil, ErrNilClient
	}

	return client.generated.EvaluatePolicyDecisionWithResponse(ctx, body, editors...)
}
