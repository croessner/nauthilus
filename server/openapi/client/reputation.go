package client

import (
	"context"
	management "github.com/croessner/nauthilus/v4/server/openapi/generated/management"
)

// LookupReputation invokes the exact administrative reputation contract with the configured backchannel credentials.
func (client *ManagementClient) LookupReputation(ctx context.Context, body management.LookupReputationJSONRequestBody, editors ...management.RequestEditorFn) (*management.LookupReputationResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.LookupReputationWithResponse(ctx, body, editors...)
}

// PutReputationOverride invokes the exact administrative reputation contract with the configured backchannel credentials.
func (client *ManagementClient) PutReputationOverride(ctx context.Context, body management.PutReputationOverrideJSONRequestBody, editors ...management.RequestEditorFn) (*management.PutReputationOverrideResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.PutReputationOverrideWithResponse(ctx, body, editors...)
}

// DeleteReputationOverride invokes the exact administrative reputation contract with the configured backchannel credentials.
func (client *ManagementClient) DeleteReputationOverride(ctx context.Context, body management.DeleteReputationOverrideJSONRequestBody, editors ...management.RequestEditorFn) (*management.DeleteReputationOverrideResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.DeleteReputationOverrideWithResponse(ctx, body, editors...)
}

// ManageReputationAllocation inspects or quiesces the configured allocation generation through the administrative contract.
func (client *ManagementClient) ManageReputationAllocation(ctx context.Context, body management.ManageReputationAllocationJSONRequestBody, editors ...management.RequestEditorFn) (*management.ManageReputationAllocationResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.ManageReputationAllocationWithResponse(ctx, body, editors...)
}
