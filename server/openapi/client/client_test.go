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
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	generatedidp "github.com/croessner/nauthilus/v3/server/openapi/generated/idp"
	management "github.com/croessner/nauthilus/v3/server/openapi/generated/management"
	"github.com/croessner/nauthilus/v3/server/openapi/requesttest"
)

const (
	supportedClientBaseURL                = "https://nauthilus.example.test"
	supportedClientBearerToken            = "supported-client-token"
	supportedClientBasicPassword          = "supported-client-secret"
	supportedClientBasicUser              = "supported-client"
	supportedClientBruteForceListPath     = "/api/v1/bruteforce/list"
	supportedClientCacheJobID             = "job-supported-cache"
	supportedClientCacheSession           = "supported-cache-session"
	supportedClientCacheUser              = "alice@example.test"
	supportedClientConfigSession          = "supported-config-session"
	supportedClientJobFinishedAt          = "2026-05-15T10:01:03Z"
	supportedClientJobResultCount         = "2"
	supportedClientJobStartedAt           = "2026-05-15T10:01:01Z"
	supportedClientBruteForceRuleName     = "default"
	supportedClientIPAddress              = "192.0.2.42"
	supportedClientOIDCCID                = "identity-proxy"
	supportedClientOIDCSessionID          = "session-reference-id"
	supportedClientOIDCSessionReference   = "opaque-session-reference"
	supportedClientOIDCUser               = "alice"
	supportedClientDiscoveryAuthEndpoint  = "https://idp.example.test/oidc/authorize"
	supportedClientDiscoveryIssuer        = "https://idp.example.test"
	supportedClientDiscoveryJWKSURI       = "https://idp.example.test/oidc/jwks"
	supportedClientDiscoveryTokenEndpoint = "https://idp.example.test/oidc/token"
	supportedClientOpenAPIField           = "openapi"
	supportedClientOpenAPIYAMLContentType = "application/yaml; charset=utf-8"
	supportedClientOpenAPIVersion         = "3.1.0"
)

var supportedClientOIDCAuthTime = time.Date(2026, time.May, 15, 10, 2, 0, 0, time.UTC)

func TestSupportedManagementClientEnqueuesCacheFlushWithBearerAuth(t *testing.T) {
	response := callSupportedManagementCacheFlush(t, BearerToken(supportedClientBearerToken), "Bearer "+supportedClientBearerToken)

	assertSupportedCacheFlushResponse(t, response)
}

func TestSupportedManagementClientEnqueuesCacheFlushWithBasicAuth(t *testing.T) {
	auth := BasicCredentials(supportedClientBasicUser, supportedClientBasicPassword)
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(supportedClientBasicUser+":"+supportedClientBasicPassword))

	response := callSupportedManagementCacheFlush(t, auth, header)

	assertSupportedCacheFlushResponse(t, response)
}

func TestSupportedManagementClientRejectsMissingBackchannelAuth(t *testing.T) {
	t.Run("empty bearer token", func(t *testing.T) {
		_, err := NewManagementClient(supportedClientBaseURL, BearerToken(""))
		if err == nil {
			t.Fatal("expected empty bearer token to fail")
		}
	})

	t.Run("empty basic username", func(t *testing.T) {
		_, err := NewManagementClient(supportedClientBaseURL, BasicCredentials("", supportedClientBasicPassword))
		if err == nil {
			t.Fatal("expected empty basic username to fail")
		}
	})

	t.Run("empty basic password", func(t *testing.T) {
		_, err := NewManagementClient(supportedClientBaseURL, BasicCredentials(supportedClientBasicUser, ""))
		if err == nil {
			t.Fatal("expected empty basic password to fail")
		}
	})
}

func TestSupportedManagementClientGetsAsyncJobStatus(t *testing.T) {
	responseBody := management.AsyncJobStatusResult{
		Session:   supportedClientCacheSession,
		Object:    definitions.CatCache,
		Operation: definitions.ServFlush,
		Result: management.AsyncJobStatusPayload{
			JobId:       new(supportedClientCacheJobID),
			Status:      new(management.AsyncJobStatusDone),
			Type:        new(definitions.CatCache),
			StartedAt:   new(supportedClientJobStartedAt),
			FinishedAt:  new(supportedClientJobFinishedAt),
			ResultCount: new(supportedClientJobResultCount),
		},
	}
	doer := requesttest.NewClientSmokeDoer(t, requesttest.ClientSmokeRoute{
		Response: responseBody,
		Headers: map[string]string{
			authorizationHeader: "Bearer " + supportedClientBearerToken,
		},
		Method: http.MethodGet,
		Path:   "/api/v1/async/jobs/" + supportedClientCacheJobID,
		Status: http.StatusOK,
	})

	client, err := NewManagementClient(
		supportedClientBaseURL,
		BearerToken(supportedClientBearerToken),
		management.WithHTTPClient(doer),
	)
	if err != nil {
		t.Fatalf("create supported management client: %v", err)
	}

	response, err := client.GetAsyncJobStatus(context.Background(), supportedClientCacheJobID)
	if err != nil {
		t.Fatalf("get async job status through supported client: %v", err)
	}

	assertSupportedAsyncJobStatusResponse(t, response)
}

func TestSupportedManagementClientUsesOpenAPIExports(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		client := newSupportedManagementClient(t, supportedOpenAPIJSONRoute("/api/v1/openapi.json"))

		response, err := client.GetOpenAPIJSON(context.Background())
		if err != nil {
			t.Fatalf("get management OpenAPI JSON: %v", err)
		}

		requireStatusCode(t, response, http.StatusOK)
		requireOpenAPIJSONVersion(t, response.JSON200)
	})

	t.Run("yaml", func(t *testing.T) {
		client := newSupportedManagementClient(t, supportedOpenAPIYAMLRoute(
			"/api/v1/openapi.yaml",
			"Nauthilus Management API",
		))

		requireRawDocumentResponse(t, func(ctx context.Context) (*http.Response, error) {
			return client.GetOpenAPIYAML(ctx)
		}, "openapi: "+supportedClientOpenAPIVersion)
	})
}

func TestSupportedManagementClientUsesCacheOperations(t *testing.T) {
	requestBody := management.FlushUserCacheJSONRequestBody{User: supportedClientCacheUser}
	responseBody := management.CacheFlushResult{
		Session:   supportedClientCacheSession,
		Object:    definitions.CatCache,
		Operation: definitions.ServFlush,
		Result: management.CacheFlushPayload{
			Status: new("flushed"),
			User:   new(supportedClientCacheUser),
		},
	}
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Request:  requestBody,
		Response: responseBody,
		Method:   http.MethodDelete,
		Path:     "/api/v1/cache/flush",
		Status:   http.StatusOK,
	})

	response, err := client.FlushUserCache(context.Background(), requestBody)
	if err != nil {
		t.Fatalf("flush user cache through supported client: %v", err)
	}

	requireCacheFlushResult(t, response)
}

func TestSupportedManagementClientListsBruteForceEntries(t *testing.T) {
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Response: supportedBruteForceListResult(),
		Method:   http.MethodGet,
		Path:     supportedClientBruteForceListPath,
		Status:   http.StatusOK,
	})

	response, err := client.ListBruteForceEntries(context.Background())
	if err != nil {
		t.Fatalf("list brute-force entries through supported client: %v", err)
	}

	requireBruteForceListResult(t, response.StatusCode(), response.JSON200)
}

func TestSupportedManagementClientListsFilteredBruteForceEntries(t *testing.T) {
	requestBody := supportedBruteForceFilterRequest()
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Request:  requestBody,
		Response: supportedBruteForceListResult(),
		Method:   http.MethodPost,
		Path:     supportedClientBruteForceListPath,
		Status:   http.StatusOK,
	})

	response, err := client.ListFilteredBruteForceEntries(context.Background(), requestBody)
	if err != nil {
		t.Fatalf("list filtered brute-force entries through supported client: %v", err)
	}

	requireBruteForceListResult(t, response.StatusCode(), response.JSON200)
}

func TestSupportedManagementClientFlushesBruteForceRule(t *testing.T) {
	requestBody := supportedBruteForceFlushRequest()
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Request:  requestBody,
		Response: supportedBruteForceFlushResult(),
		Method:   http.MethodDelete,
		Path:     "/api/v1/bruteforce/flush",
		Status:   http.StatusOK,
	})

	response, err := client.FlushBruteForceRule(context.Background(), requestBody)
	if err != nil {
		t.Fatalf("flush brute-force rule through supported client: %v", err)
	}

	requireBruteForceFlushResult(t, response)
}

func TestSupportedManagementClientEnqueuesBruteForceRuleFlush(t *testing.T) {
	requestBody := supportedBruteForceFlushRequest()
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Request:  requestBody,
		Response: supportedAsyncAccepted(definitions.CatBruteForce),
		Method:   http.MethodDelete,
		Path:     "/api/v1/bruteforce/flush/async",
		Status:   http.StatusAccepted,
	})

	response, err := client.EnqueueBruteForceRuleFlush(context.Background(), requestBody)
	if err != nil {
		t.Fatalf("enqueue brute-force flush through supported client: %v", err)
	}

	requireStatusCode(t, response, http.StatusAccepted)
}

func TestSupportedManagementClientLoadsRuntimeConfig(t *testing.T) {
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Response: management.ConfigLoadResult{
			Session:   supportedClientConfigSession,
			Object:    definitions.CatConfig,
			Operation: definitions.ServLoad,
			Result:    `{"runtime":{"workers":1}}`,
		},
		Method: http.MethodGet,
		Path:   "/api/v1/config/load",
		Status: http.StatusOK,
	})

	response, err := client.LoadRuntimeConfig(context.Background())
	if err != nil {
		t.Fatalf("load runtime config through supported client: %v", err)
	}

	requireStatusCode(t, response, http.StatusOK)
	requireConfigLoadResult(t, response)
}

func TestSupportedManagementClientListsOIDCSessions(t *testing.T) {
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Response: management.OIDCSessions{
			Sessions: []management.OIDCSessionSummary{
				{
					Id:       supportedClientOIDCSessionID,
					ClientId: supportedClientOIDCCID,
					UserId:   supportedClientOIDCUser,
					AuthTime: supportedClientOIDCAuthTime,
				},
			},
		},
		Method: http.MethodGet,
		Path:   supportedOIDCSessionsPath(),
		Status: http.StatusOK,
	})

	response, err := client.ListOIDCSessions(context.Background(), supportedClientOIDCUser)
	if err != nil {
		t.Fatalf("list OIDC sessions through supported client: %v", err)
	}

	requireStatusCode(t, response, http.StatusOK)
	requireOIDCSession(t, response)
}

func TestSupportedManagementClientDeletesOIDCSessions(t *testing.T) {
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Method: http.MethodDelete,
		Path:   supportedOIDCSessionsPath(),
		Status: http.StatusNoContent,
	})

	response, err := client.DeleteOIDCSessions(context.Background(), supportedClientOIDCUser)
	if err != nil {
		t.Fatalf("delete OIDC sessions through supported client: %v", err)
	}

	requireStatusCode(t, response, http.StatusNoContent)
}

func TestSupportedManagementClientDeletesOIDCSession(t *testing.T) {
	client := newSupportedManagementClient(t, requesttest.ClientSmokeRoute{
		Method: http.MethodDelete,
		Path:   supportedOIDCSessionPath(),
		Status: http.StatusNoContent,
	})

	response, err := client.DeleteOIDCSession(
		context.Background(),
		supportedClientOIDCUser,
		supportedClientOIDCSessionReference,
	)
	if err != nil {
		t.Fatalf("delete OIDC session through supported client: %v", err)
	}

	requireStatusCode(t, response, http.StatusNoContent)
}

func TestSupportedIDPDiscoveryClientGetsOIDCDiscovery(t *testing.T) {
	discovery := generatedidp.OIDCDiscovery{
		AuthorizationEndpoint: supportedClientDiscoveryAuthEndpoint,
		Issuer:                supportedClientDiscoveryIssuer,
		JwksUri:               supportedClientDiscoveryJWKSURI,
		TokenEndpoint:         supportedClientDiscoveryTokenEndpoint,
	}
	doer := requesttest.NewClientSmokeDoer(t, requesttest.ClientSmokeRoute{
		Response: discovery,
		Method:   http.MethodGet,
		Path:     "/.well-known/openid-configuration",
		Status:   http.StatusOK,
	})

	client, err := NewIDPDiscoveryClient(supportedClientBaseURL, generatedidp.WithHTTPClient(doer))
	if err != nil {
		t.Fatalf("create supported IDP discovery client: %v", err)
	}

	response, err := client.GetOIDCDiscovery(context.Background())
	if err != nil {
		t.Fatalf("get OIDC discovery through supported client: %v", err)
	}

	assertSupportedDiscoveryResponse(t, response)
}

func TestSupportedIDPDiscoveryClientUsesPublicDocuments(t *testing.T) {
	t.Run("openapi json", func(t *testing.T) {
		client := newSupportedIDPDiscoveryClient(t, supportedOpenAPIJSONRoute("/.well-known/openapi.json"))

		response, err := client.GetPublicOpenAPIJSON(context.Background())
		if err != nil {
			t.Fatalf("get public IDP OpenAPI JSON: %v", err)
		}

		requireStatusCode(t, response, http.StatusOK)
		requireOpenAPIJSONVersion(t, response.JSON200)
	})

	t.Run("openapi yaml", func(t *testing.T) {
		client := newSupportedIDPDiscoveryClient(t, supportedOpenAPIYAMLRoute(
			"/.well-known/openapi.yaml",
			"Nauthilus IdP API",
		))

		requireRawDocumentResponse(t, func(ctx context.Context) (*http.Response, error) {
			return client.GetPublicOpenAPIYAML(ctx)
		}, "Nauthilus IdP API")
	})
}

func TestSupportedIDPDiscoveryClientGetsJWKSAndSAMLMetadata(t *testing.T) {
	t.Run("jwks", func(t *testing.T) {
		client := newSupportedIDPDiscoveryClient(t, requesttest.ClientSmokeRoute{
			Response: generatedidp.JWKS{Keys: []map[string]any{{"kid": "supported-key"}}},
			Method:   http.MethodGet,
			Path:     "/oidc/jwks",
			Status:   http.StatusOK,
		})

		response, err := client.GetOIDCJWKS(context.Background())
		if err != nil {
			t.Fatalf("get OIDC JWKS through supported client: %v", err)
		}

		requireStatusCode(t, response, http.StatusOK)
		requireJWKSResponse(t, response)
	})

	t.Run("saml metadata", func(t *testing.T) {
		client := newSupportedIDPDiscoveryClient(t, supportedRawDocumentRoute(
			"/saml/metadata",
			"application/samlmetadata+xml; charset=utf-8",
			`<EntityDescriptor entityID="https://idp.example.test/saml/metadata"></EntityDescriptor>`,
		))

		requireRawDocumentResponse(t, func(ctx context.Context) (*http.Response, error) {
			return client.GetSAMLMetadata(ctx)
		}, "EntityDescriptor")
	})
}

func newSupportedManagementClient(t testing.TB, route requesttest.ClientSmokeRoute) *ManagementClient {
	t.Helper()

	if route.Headers == nil {
		route.Headers = make(map[string]string)
	}

	route.Headers[authorizationHeader] = "Bearer " + supportedClientBearerToken

	doer := requesttest.NewClientSmokeDoer(t, route)

	client, err := NewManagementClient(
		supportedClientBaseURL,
		BearerToken(supportedClientBearerToken),
		management.WithHTTPClient(doer),
	)
	if err != nil {
		t.Fatalf("create supported management client: %v", err)
	}

	return client
}

func newSupportedIDPDiscoveryClient(t testing.TB, route requesttest.ClientSmokeRoute) *IDPDiscoveryClient {
	t.Helper()

	doer := requesttest.NewClientSmokeDoer(t, route)

	client, err := NewIDPDiscoveryClient(supportedClientBaseURL, generatedidp.WithHTTPClient(doer))
	if err != nil {
		t.Fatalf("create supported IDP discovery client: %v", err)
	}

	return client
}

func supportedOpenAPIJSONRoute(path string) requesttest.ClientSmokeRoute {
	return requesttest.ClientSmokeRoute{
		Response: map[string]any{
			supportedClientOpenAPIField: supportedClientOpenAPIVersion,
		},
		Method: http.MethodGet,
		Path:   path,
		Status: http.StatusOK,
	}
}

func supportedOpenAPIYAMLRoute(path string, title string) requesttest.ClientSmokeRoute {
	body := "openapi: " + supportedClientOpenAPIVersion + "\ninfo:\n  title: " + title + "\n"

	return supportedRawDocumentRoute(path, supportedClientOpenAPIYAMLContentType, body)
}

func supportedRawDocumentRoute(path string, contentType string, body string) requesttest.ClientSmokeRoute {
	return requesttest.ClientSmokeRoute{
		ResponseBody: []byte(body),
		ContentType:  contentType,
		Method:       http.MethodGet,
		Path:         path,
		Status:       http.StatusOK,
	}
}

func supportedOIDCSessionsPath() string {
	return "/api/v1/oidc/sessions/" + supportedClientOIDCUser
}

func supportedOIDCSessionPath() string {
	return supportedOIDCSessionsPath() + "/" + supportedClientOIDCSessionReference
}

func callSupportedManagementCacheFlush(
	t testing.TB,
	auth BackchannelAuth,
	expectedAuthorizationHeader string,
) *management.EnqueueUserCacheFlushResponse {
	t.Helper()

	requestBody := management.EnqueueUserCacheFlushJSONRequestBody{User: supportedClientCacheUser}
	responseBody := supportedAsyncAccepted(definitions.CatCache)
	doer := requesttest.NewClientSmokeDoer(t, requesttest.ClientSmokeRoute{
		Request:  requestBody,
		Response: responseBody,
		Headers: map[string]string{
			authorizationHeader: expectedAuthorizationHeader,
		},
		Method: http.MethodDelete,
		Path:   "/api/v1/cache/flush/async",
		Status: http.StatusAccepted,
	})

	client, err := NewManagementClient(supportedClientBaseURL, auth, management.WithHTTPClient(doer))
	if err != nil {
		t.Fatalf("create supported management client: %v", err)
	}

	response, err := client.EnqueueUserCacheFlush(context.Background(), requestBody)
	if err != nil {
		t.Fatalf("enqueue cache flush through supported client: %v", err)
	}

	return response
}

func supportedAsyncAccepted(object string) management.AsyncAccepted {
	return management.AsyncAccepted{
		Session:   supportedClientCacheSession,
		Object:    object,
		Operation: definitions.ServFlush,
		Result: management.AsyncAcceptedPayload{
			JobId:  supportedClientCacheJobID,
			Status: management.AsyncAcceptedStatusQueued,
		},
	}
}

func supportedBruteForceFilterRequest() management.BruteForceFilterRequest {
	accounts := []string{supportedClientCacheUser}
	ipAddresses := []string{supportedClientIPAddress}

	return management.BruteForceFilterRequest{
		Accounts:    &accounts,
		IpAddresses: &ipAddresses,
	}
}

func supportedBruteForceFlushRequest() management.BruteForceFlushRequest {
	return management.BruteForceFlushRequest{
		IpAddress: supportedClientIPAddress,
		OidcCid:   new(supportedClientOIDCCID),
		Protocol:  new(definitions.ProtoOIDC),
		RuleName:  supportedClientBruteForceRuleName,
	}
}

func supportedBruteForceListResult() management.BruteForceListResult {
	return management.BruteForceListResult{
		Session:   supportedClientCacheSession,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServList,
		Result: []any{
			map[string]any{
				"account":    supportedClientCacheUser,
				"ip_address": supportedClientIPAddress,
				"rule_name":  supportedClientBruteForceRuleName,
			},
		},
	}
}

func supportedBruteForceFlushResult() management.BruteForceFlushResult {
	return management.BruteForceFlushResult{
		Session:   supportedClientCacheSession,
		Object:    definitions.CatBruteForce,
		Operation: definitions.ServFlush,
		Result: management.BruteForceFlushPayload{
			IpAddress: new(supportedClientIPAddress),
			RuleName:  new(supportedClientBruteForceRuleName),
			Status:    new("flushed"),
		},
	}
}

func assertSupportedCacheFlushResponse(t testing.TB, response *management.EnqueueUserCacheFlushResponse) {
	t.Helper()

	if response.StatusCode() != http.StatusAccepted {
		t.Fatalf("status code = %d, want %d", response.StatusCode(), http.StatusAccepted)
	}

	if response.JSON202 == nil {
		t.Fatal("JSON202 response missing")
	}

	if response.JSON202.Session != supportedClientCacheSession {
		t.Fatalf("session = %q, want %q", response.JSON202.Session, supportedClientCacheSession)
	}

	if response.JSON202.Object != definitions.CatCache {
		t.Fatalf("object = %q, want %q", response.JSON202.Object, definitions.CatCache)
	}

	if response.JSON202.Operation != definitions.ServFlush {
		t.Fatalf("operation = %q, want %q", response.JSON202.Operation, definitions.ServFlush)
	}

	if response.JSON202.Result.JobId != supportedClientCacheJobID {
		t.Fatalf("jobId = %q, want %q", response.JSON202.Result.JobId, supportedClientCacheJobID)
	}

	if response.JSON202.Result.Status != management.AsyncAcceptedStatusQueued {
		t.Fatalf("status = %q, want %q", response.JSON202.Result.Status, management.AsyncAcceptedStatusQueued)
	}
}

func assertSupportedAsyncJobStatusResponse(t testing.TB, response *management.GetAsyncJobStatusResponse) {
	t.Helper()

	if response.StatusCode() != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.StatusCode(), http.StatusOK)
	}

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")
	}

	if response.JSON200.Session != supportedClientCacheSession {
		t.Fatalf("session = %q, want %q", response.JSON200.Session, supportedClientCacheSession)
	}

	if response.JSON200.Object != definitions.CatCache {
		t.Fatalf("object = %q, want %q", response.JSON200.Object, definitions.CatCache)
	}

	if response.JSON200.Operation != definitions.ServFlush {
		t.Fatalf("operation = %q, want %q", response.JSON200.Operation, definitions.ServFlush)
	}

	requireStringPointer(t, "jobId", response.JSON200.Result.JobId, supportedClientCacheJobID)
	requireJobStatusPointer(t, "status", response.JSON200.Result.Status, management.AsyncJobStatusDone)
	requireStringPointer(t, "result count", response.JSON200.Result.ResultCount, supportedClientJobResultCount)
}

func assertSupportedDiscoveryResponse(t testing.TB, response *generatedidp.GetOIDCDiscoveryResponse) {
	t.Helper()

	if response.StatusCode() != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.StatusCode(), http.StatusOK)
	}

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")
	}

	if response.JSON200.Issuer != supportedClientDiscoveryIssuer {
		t.Fatalf("issuer = %q, want %q", response.JSON200.Issuer, supportedClientDiscoveryIssuer)
	}

	if response.JSON200.AuthorizationEndpoint != supportedClientDiscoveryAuthEndpoint {
		t.Fatalf("authorization endpoint = %q, want %q", response.JSON200.AuthorizationEndpoint, supportedClientDiscoveryAuthEndpoint)
	}

	if response.JSON200.TokenEndpoint != supportedClientDiscoveryTokenEndpoint {
		t.Fatalf("token endpoint = %q, want %q", response.JSON200.TokenEndpoint, supportedClientDiscoveryTokenEndpoint)
	}

	if response.JSON200.JwksUri != supportedClientDiscoveryJWKSURI {
		t.Fatalf("jwks uri = %q, want %q", response.JSON200.JwksUri, supportedClientDiscoveryJWKSURI)
	}
}

type statusCoder interface {
	StatusCode() int
}

func requireStatusCode(t testing.TB, response statusCoder, want int) {
	t.Helper()

	if response.StatusCode() != want {
		t.Fatalf("status code = %d, want %d", response.StatusCode(), want)
	}
}

func requireHTTPStatusCode(t testing.TB, response *http.Response, want int) {
	t.Helper()

	if response.StatusCode != want {
		t.Fatalf("status code = %d, want %d", response.StatusCode, want)
	}
}

func requireRawBodyContains(t testing.TB, body io.Reader, want string) {
	t.Helper()

	content, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read raw response body: %v", err)
	}

	if !strings.Contains(string(content), want) {
		t.Fatalf("response body does not contain %q: %q", want, string(content))
	}
}

func requireRawDocumentResponse(
	t testing.TB,
	call func(context.Context) (*http.Response, error),
	want string,
) {
	t.Helper()

	response, err := call(context.Background())
	if err != nil {
		t.Fatalf("get raw document through supported client: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	requireHTTPStatusCode(t, response, http.StatusOK)
	requireRawBodyContains(t, response.Body, want)
}

func requireOpenAPIJSONVersion(t testing.TB, document *map[string]any) {
	t.Helper()

	if document == nil {
		t.Fatal("JSON200 response missing")

		return
	}

	if (*document)[supportedClientOpenAPIField] != supportedClientOpenAPIVersion {
		t.Fatalf(
			"openapi version = %#v, want %s",
			(*document)[supportedClientOpenAPIField],
			supportedClientOpenAPIVersion,
		)
	}
}

func requireBruteForceListResult(t testing.TB, statusCode int, result *management.BruteForceListResult) {
	t.Helper()

	if statusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", statusCode, http.StatusOK)
	}

	if result == nil {
		t.Fatal("JSON200 response missing")

		return
	}

	if result.Object != definitions.CatBruteForce {
		t.Fatalf("object = %q, want %q", result.Object, definitions.CatBruteForce)
	}

	if len(result.Result) != 1 {
		t.Fatalf("result length = %d, want 1", len(result.Result))
	}
}

func requireBruteForceFlushResult(t testing.TB, response *management.FlushBruteForceRuleResponse) {
	t.Helper()

	requireStatusCode(t, response, http.StatusOK)

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")

		return
	}

	if response.JSON200.Object != definitions.CatBruteForce {
		t.Fatalf("object = %q, want %q", response.JSON200.Object, definitions.CatBruteForce)
	}

	requireStringPointer(t, "rule name", response.JSON200.Result.RuleName, supportedClientBruteForceRuleName)
}

func requireCacheFlushResult(t testing.TB, response *management.FlushUserCacheResponse) {
	t.Helper()

	requireStatusCode(t, response, http.StatusOK)

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")

		return
	}

	requireStringPointer(t, "cache user", response.JSON200.Result.User, supportedClientCacheUser)
}

func requireConfigLoadResult(t testing.TB, response *management.LoadRuntimeConfigResponse) {
	t.Helper()

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")

		return
	}

	if response.JSON200.Object != definitions.CatConfig {
		t.Fatalf("object = %q, want %q", response.JSON200.Object, definitions.CatConfig)
	}

	if response.JSON200.Operation != definitions.ServLoad {
		t.Fatalf("operation = %q, want %q", response.JSON200.Operation, definitions.ServLoad)
	}
}

func requireOIDCSession(t testing.TB, response *management.ListOIDCSessionsResponse) {
	t.Helper()

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")

		return
	}

	if len(response.JSON200.Sessions) != 1 {
		t.Fatalf("sessions length = %d, want 1", len(response.JSON200.Sessions))
	}

	session := response.JSON200.Sessions[0]

	if session.Id != supportedClientOIDCSessionID {
		t.Fatalf("session id = %q, want %q", session.Id, supportedClientOIDCSessionID)
	}

	if session.ClientId != supportedClientOIDCCID {
		t.Fatalf("client id = %q, want %q", session.ClientId, supportedClientOIDCCID)
	}

	if session.UserId != supportedClientOIDCUser {
		t.Fatalf("user id = %q, want %q", session.UserId, supportedClientOIDCUser)
	}
}

func requireJWKSResponse(t testing.TB, response *generatedidp.GetOIDCJWKSResponse) {
	t.Helper()

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")

		return
	}

	if len(response.JSON200.Keys) != 1 {
		t.Fatalf("JWKS key count = %d, want 1", len(response.JSON200.Keys))
	}
}

func requireStringPointer(t testing.TB, field string, got *string, want string) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s is nil, want %q", field, want)

		return
	}

	if *got != want {
		t.Fatalf("%s = %q, want %q", field, *got, want)
	}
}

func requireJobStatusPointer(
	t testing.TB,
	field string,
	got *management.AsyncJobStatusPayloadStatus,
	want management.AsyncJobStatusPayloadStatus,
) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s is nil, want %q", field, want)

		return
	}

	if *got != want {
		t.Fatalf("%s = %q, want %q", field, *got, want)
	}
}
