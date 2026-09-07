package client

import (
	management "github.com/croessner/nauthilus/v4/server/openapi/generated/management"
	"github.com/croessner/nauthilus/v4/server/openapi/requesttest"
	"net/http"
	"testing"
)

func TestSupportedManagementClientPreservesReputationFailureAndBodyPrivacy(t *testing.T) {
	body := management.LookupReputationJSONRequestBody{Kind: "ip", Subject: supportedClientIPAddress}
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Request: body, Response: management.ReputationManagementError{Error: "Service Unavailable"},
		Method: http.MethodPost, Path: "/api/v1/custom/reputation/lookup", Status: http.StatusServiceUnavailable,
	})

	response, err := client.LookupReputation(t.Context(), body)
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode() != http.StatusServiceUnavailable || response.JSON503 == nil {
		t.Fatal("client hid unknown primary outcome")
	}
}
