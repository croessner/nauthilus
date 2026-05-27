// Copyright (C) 2026 Christian Rößner
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

package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/compiler"
	"github.com/croessner/nauthilus/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	requestClientIPPresentAttribute   = "request.client.ip.present"
	requestClientIPTrustedAttribute   = "request.client.ip.trusted"
	requestClientIPSourceAttribute    = "request.client.ip.source"
	requestCallerIPPresentAttribute   = "request.caller.ip.present"
	requestCallerIPSourceAttribute    = "request.caller.ip.source"
	requestLocalIPPresentAttribute    = "request.local.ip.present"
	requestLocalPortPresentAttribute  = "request.local.port.present"
	requestTransportKindAttribute     = "request.transport.kind"
	requestListenerNameAttribute      = "request.listener.name"
	requestConnectionTLSAttribute     = "request.connection.tls"
	requestInitiatorKindAttribute     = "request.initiator.kind"
	requestHTTPRouteAttribute         = "request.http.route"
	requestGRPCMethodAttribute        = "request.grpc.method"
	requestIDPClientIDAttribute       = "request.idp.client_id"
	requestSAMLServiceProviderAttr    = "request.saml.sp_entity_id"
	requestClientIPSourceDirectPeer   = "direct_peer"
	requestClientIPSourceTrustedProxy = "trusted_proxy_header"
	requestClientIPSourceMetadata     = "metadata"
	requestContextDirectPeerIP        = "203.0.113.10"
	requestContextCallerIP            = "198.51.100.25"
	requestContextLocalIP             = "10.0.0.25"
	requestContextLocalPort           = "993"
	requestContextLocalEndpointPolicy = "deny_local_endpoint"
	requestContextLoopbackIP          = "127.0.0.1"
	requestContextClientIPHeader      = "Client-IP"
	requestContextOIDCClientID        = "oidc-client"
	requestContextLDAPConfigRef       = "auth.backends.ldap"
)

func TestRequestContextDirectPeerEmitsTypedClientIPFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = requestContextDirectPeerIP
	ctx.Request.RemoteAddr = requestContextDirectPeerIP + ":42311"

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextValue(t, policyReport, policy.AttributeRequestClientIP, netip.MustParseAddr(requestContextDirectPeerIP))
	assertRequestContextValue(t, policyReport, requestClientIPPresentAttribute, true)
	assertRequestContextValue(t, policyReport, requestClientIPTrustedAttribute, true)
	assertRequestContextValue(t, policyReport, requestClientIPSourceAttribute, requestClientIPSourceDirectPeer)
	assertRequestContextValue(t, policyReport, requestTransportKindAttribute, "http")
	assertRequestContextValue(t, policyReport, requestListenerNameAttribute, "http")
	assertRequestContextValue(t, policyReport, requestConnectionTLSAttribute, false)
	assertRequestContextValue(t, policyReport, requestInitiatorKindAttribute, "external_user")
}

func TestRequestContextEmptyClientIPFailsClosed(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = ""
	ctx.Request.RemoteAddr = ""

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextMissing(t, policyReport, policy.AttributeRequestClientIP)
	assertRequestContextValue(t, policyReport, requestClientIPPresentAttribute, false)
	assertRequestContextValue(t, policyReport, requestClientIPTrustedAttribute, false)
}

func TestRequestContextInvalidClientIPDoesNotMatchCIDRPolicy(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, compileClientIPCIDRPolicySnapshotForTest(t, cfg, "deny_loopback", "127.0.0.0/8"))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "not-an-ip"
	ctx.Request.RemoteAddr = "not-an-ip:42311"

	final, authoritative := auth.configuredPolicyPreAuthDecision(ctx)
	if !authoritative {
		t.Fatal("configured pre-auth policy should be authoritative for this test")
	}

	if final != nil {
		t.Fatalf("invalid client IP selected policy %#v, want no match", final)
	}

	policyReport := requestContextReport(t, auth, ctx)
	assertRequestContextMissing(t, policyReport, policy.AttributeRequestClientIP)
	assertRequestContextValue(t, policyReport, requestClientIPPresentAttribute, false)
}

func TestRequestContextLoopbackIsTypedPolicyFact(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, compileClientIPCIDRPolicySnapshotForTest(t, cfg, "deny_loopback", "127.0.0.0/8"))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = requestContextLoopbackIP
	ctx.Request.RemoteAddr = requestContextLoopbackIP + ":42311"

	final, authoritative := auth.configuredPolicyPreAuthDecision(ctx)
	if !authoritative {
		t.Fatal("configured pre-auth policy should be authoritative for this test")
	}

	if final == nil || final.PolicyName != "deny_loopback" {
		t.Fatalf("policy decision = %#v, want deny_loopback", final)
	}

	policyReport := requestContextReport(t, auth, ctx)
	assertRequestContextValue(t, policyReport, policy.AttributeRequestClientIP, netip.MustParseAddr(requestContextLoopbackIP))
	assertRequestContextValue(t, policyReport, requestClientIPTrustedAttribute, true)
}

func TestRequestContextTrustedProxyHeaderIsExplicitlyTrusted(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.TrustedProxies = []string{"198.51.100.10"}
	cfg.Server.DefaultHTTPRequestHeader.ClientIP = requestContextClientIPHeader
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.44"
	ctx.Request.RemoteAddr = "198.51.100.10:443"
	ctx.Request.Header.Set(requestContextClientIPHeader, "203.0.113.44")

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextValue(t, policyReport, policy.AttributeRequestClientIP, netip.MustParseAddr("203.0.113.44"))
	assertRequestContextValue(t, policyReport, requestClientIPPresentAttribute, true)
	assertRequestContextValue(t, policyReport, requestClientIPTrustedAttribute, true)
	assertRequestContextValue(t, policyReport, requestClientIPSourceAttribute, requestClientIPSourceTrustedProxy)
}

func TestRequestContextUntrustedHeaderCandidateIsNotTrusted(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.TrustedProxies = []string{"198.51.100.10"}
	cfg.Server.DefaultHTTPRequestHeader.ClientIP = requestContextClientIPHeader
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.45"
	ctx.Request.RemoteAddr = "198.51.100.99:443"
	ctx.Request.Header.Set(requestContextClientIPHeader, "203.0.113.45")

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextValue(t, policyReport, policy.AttributeRequestClientIP, netip.MustParseAddr("203.0.113.45"))
	assertRequestContextValue(t, policyReport, requestClientIPPresentAttribute, true)
	assertRequestContextValue(t, policyReport, requestClientIPTrustedAttribute, false)
	assertRequestContextValue(t, policyReport, requestClientIPSourceAttribute, requestClientIPSourceMetadata)
}

func TestRequestContextGRPCMetadataCandidateIsNotTrusted(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServGRPC
	auth.Request.ClientIP = "203.0.113.46"
	auth.Request.RequestMetadata = map[string][]string{
		"x-forwarded-for": {"203.0.113.46"},
	}
	ctx.Request.RemoteAddr = ""

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextValue(t, policyReport, policy.AttributeRequestClientIP, netip.MustParseAddr("203.0.113.46"))
	assertRequestContextValue(t, policyReport, requestClientIPPresentAttribute, true)
	assertRequestContextValue(t, policyReport, requestClientIPTrustedAttribute, false)
	assertRequestContextValue(t, policyReport, requestClientIPSourceAttribute, requestClientIPSourceMetadata)
	assertRequestContextValue(t, policyReport, requestTransportKindAttribute, "grpc")
	assertRequestContextValue(t, policyReport, requestListenerNameAttribute, "grpc.authority")
}

func TestRequestContextEmitsCallerAndLocalEndpointFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.50"
	auth.Request.XLocalIP = requestContextLocalIP
	auth.Request.XPort = requestContextLocalPort
	ctx.Request.RemoteAddr = requestContextCallerIP + ":44321"

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextValue(t, policyReport, policy.AttributeRequestCallerIP, netip.MustParseAddr(requestContextCallerIP))
	assertRequestContextValue(t, policyReport, requestCallerIPPresentAttribute, true)
	assertRequestContextValue(t, policyReport, requestCallerIPSourceAttribute, requestClientIPSourceDirectPeer)
	assertRequestContextValue(t, policyReport, policy.AttributeRequestLocalIP, netip.MustParseAddr(requestContextLocalIP))
	assertRequestContextValue(t, policyReport, requestLocalIPPresentAttribute, true)
	assertRequestContextValue(t, policyReport, policy.AttributeRequestLocalPort, requestContextLocalPort)
	assertRequestContextValue(t, policyReport, requestLocalPortPresentAttribute, true)
}

func TestRequestContextInvalidLocalEndpointFailsClosed(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.51"
	auth.Request.XLocalIP = "not-an-ip"
	auth.Request.XPort = ""
	ctx.Request.RemoteAddr = requestContextCallerIP + ":44322"

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextMissing(t, policyReport, policy.AttributeRequestLocalIP)
	assertRequestContextValue(t, policyReport, requestLocalIPPresentAttribute, false)
	assertRequestContextMissing(t, policyReport, policy.AttributeRequestLocalPort)
	assertRequestContextValue(t, policyReport, requestLocalPortPresentAttribute, false)
}

func TestRequestContextCallerAndLocalEndpointDriveAuthDecisionPolicy(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, compileCallerLocalEndpointPolicySnapshotForTest(t, cfg))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.52"
	auth.Request.XLocalIP = requestContextLocalIP
	auth.Request.XPort = requestContextLocalPort
	ctx.Request.RemoteAddr = requestContextCallerIP + ":44323"
	recordFailedBackendForRequestAttributeTest(t, auth, ctx)

	final, authoritative := auth.configuredPolicyAuthDecision(ctx)
	if !authoritative {
		t.Fatal("configured auth policy should be authoritative for this test")
	}

	if final == nil || final.PolicyName != requestContextLocalEndpointPolicy {
		t.Fatalf("policy decision = %#v, want %s", final, requestContextLocalEndpointPolicy)
	}
}

func TestRequestContextHTTPRouteIsEmittedWhenAvailable(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, _, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.48"

	routeSeen := false
	router := gin.New()
	router.POST("/api/v1/auth/:service", func(ctx *gin.Context) {
		routeSeen = true
		auth.Request.HTTPClientContext = ctx
		auth.Request.HTTPClientRequest = ctx.Request
		ctx.Request.RemoteAddr = "203.0.113.48:42311"

		policyReport := requestContextReport(t, auth, ctx)
		assertRequestContextValue(t, policyReport, requestHTTPRouteAttribute, "/api/v1/auth/:service")
	})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", http.NoBody)
	router.ServeHTTP(httptest.NewRecorder(), request)

	if !routeSeen {
		t.Fatal("test route was not executed")
	}
}

func TestRequestContextGRPCMethodIsEmittedWhenAvailable(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServGRPC
	auth.Request.ClientIP = "203.0.113.49"
	ctx.Request.RemoteAddr = ""
	ctx.Request = ctx.Request.WithContext(ContextWithGRPCMethod(
		ctx.Request.Context(),
		"/nauthilus.auth.v1.AuthService/Authenticate",
	))

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextValue(t, policyReport, requestGRPCMethodAttribute, "/nauthilus.auth.v1.AuthService/Authenticate")
}

func TestRequestContextOptionalClientIdentifiers(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, requestContextSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "203.0.113.47"
	auth.Request.OIDCCID = requestContextOIDCClientID
	auth.Request.SAMLEntityID = "https://sp.example.test/saml"
	ctx.Request.RemoteAddr = "203.0.113.47:42311"

	policyReport := requestContextReport(t, auth, ctx)

	assertRequestContextValue(t, policyReport, requestIDPClientIDAttribute, requestContextOIDCClientID)
	assertRequestContextValue(t, policyReport, requestSAMLServiceProviderAttr, "https://sp.example.test/saml")
}

func TestRequestContextAttributesDoNotChangePoliciesWithoutNewFacts(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, compileBackendFailurePolicySnapshotForTest(t, cfg))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.ClientIP = "not-an-ip"
	recordFailedBackendForRequestAttributeTest(t, auth, ctx)

	final, authoritative := auth.configuredPolicyAuthDecision(ctx)
	if !authoritative {
		t.Fatal("configured auth policy should be authoritative for this test")
	}

	if final == nil || final.PolicyName != "deny_failed_backend" {
		t.Fatalf("policy decision = %#v, want deny_failed_backend", final)
	}
}

func requestContextSnapshotForTest() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    301,
		Mode:          policyModeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
	}
}

func requestContextReport(t *testing.T, auth *AuthState, ctx *gin.Context) *report.DecisionReport {
	t.Helper()

	policyCtx := auth.PolicyDecisionContext(ctx)
	if policyCtx == nil {
		t.Fatal("missing policy decision context")
	}

	return policyCtx.Report()
}

func compileClientIPCIDRPolicySnapshotForTest(
	t *testing.T,
	cfg *config.FileSettings,
	policyName string,
	network string,
) *policyruntime.Snapshot {
	t.Helper()

	cfg.Auth = &config.AuthSection{
		Policy: config.AuthPolicySection{
			Mode:          policyModeEnforce,
			DefaultPolicy: policy.BuiltinDefaultSet,
			Sets: config.PolicySetsConfig{
				Networks: map[string][]string{
					"guard_sources": {network},
				},
			},
			Policies: []config.PolicyRuleConfig{
				{
					Name:  policyName,
					Stage: string(policy.StagePreAuth),
					If: config.PolicyConditionConfig{
						Attribute:    policy.AttributeRequestClientIP,
						CIDRContains: "@network.guard_sources",
					},
					Then: config.PolicyThenConfig{
						Decision:       string(policy.DecisionDeny),
						ResponseMarker: policy.ResponseMarkerFail,
					},
				},
			},
		},
	}

	return compileRequestContextSnapshotForTest(t, cfg)
}

func compileBackendFailurePolicySnapshotForTest(t *testing.T, cfg *config.FileSettings) *policyruntime.Snapshot {
	t.Helper()

	cfg.Auth = &config.AuthSection{
		Policy: config.AuthPolicySection{
			Mode:          policyModeEnforce,
			DefaultPolicy: policy.BuiltinDefaultSet,
			Checks: []config.PolicyCheckConfig{
				{
					Name:      requestAttributeLDAPBackendCheck,
					Type:      policy.CheckTypeLDAPBackend,
					Stage:     string(policy.StageAuthBackend),
					ConfigRef: requestContextLDAPConfigRef,
				},
			},
			Policies: []config.PolicyRuleConfig{
				{
					Name:  "deny_failed_backend",
					Stage: string(policy.StageAuthDecision),
					If: config.PolicyConditionConfig{
						Attribute: policy.AttributeAuthenticated,
						Is:        false,
					},
					Then: config.PolicyThenConfig{
						Decision:       string(policy.DecisionDeny),
						ResponseMarker: policy.ResponseMarkerFail,
					},
				},
			},
		},
	}

	return compileRequestContextSnapshotForTest(t, cfg)
}

func compileRequestContextSnapshotForTest(t *testing.T, cfg *config.FileSettings) *policyruntime.Snapshot {
	t.Helper()

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{
		Config:     cfg,
		Generation: 302,
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	return snapshot
}

// compileCallerLocalEndpointPolicySnapshotForTest builds an auth-decision policy using caller and local endpoint facts.
func compileCallerLocalEndpointPolicySnapshotForTest(t *testing.T, cfg *config.FileSettings) *policyruntime.Snapshot {
	t.Helper()

	cfg.Auth = &config.AuthSection{
		Policy: config.AuthPolicySection{
			Mode:          policyModeEnforce,
			DefaultPolicy: policy.BuiltinDefaultSet,
			Sets: config.PolicySetsConfig{
				Networks: map[string][]string{
					"dovecot_callers":        {requestContextCallerIP + "/32"},
					"dovecot_local_endpoint": {"10.0.0.0/8"},
				},
			},
			Policies: []config.PolicyRuleConfig{
				{
					Name:  requestContextLocalEndpointPolicy,
					Stage: string(policy.StageAuthDecision),
					If: config.PolicyConditionConfig{
						All: []config.PolicyConditionConfig{
							{Attribute: policy.AttributeRequestCallerIPPresent, Is: true},
							{Attribute: policy.AttributeRequestCallerIP, CIDRContains: "@network.dovecot_callers"},
							{Attribute: policy.AttributeRequestLocalIPPresent, Is: true},
							{Attribute: policy.AttributeRequestLocalIP, CIDRContains: "@network.dovecot_local_endpoint"},
							{Attribute: policy.AttributeRequestLocalPort, Eq: requestContextLocalPort},
						},
					},
					Then: config.PolicyThenConfig{
						Decision:       string(policy.DecisionDeny),
						ResponseMarker: policy.ResponseMarkerFail,
					},
				},
			},
		},
	}

	return compileRequestContextSnapshotForTest(t, cfg)
}

func assertRequestContextValue(t *testing.T, policyReport *report.DecisionReport, attribute string, want any) {
	t.Helper()

	value, ok := policyReport.Attributes[attribute]
	if !ok {
		t.Fatalf("missing policy attribute %s", attribute)
	}

	if value.Value != want {
		t.Fatalf("policy attribute %s = %#v, want %#v", attribute, value.Value, want)
	}
}

func assertRequestContextMissing(t *testing.T, policyReport *report.DecisionReport, attribute string) {
	t.Helper()

	if _, ok := policyReport.Attributes[attribute]; ok {
		t.Fatalf("policy attribute %s was emitted, want missing", attribute)
	}
}
