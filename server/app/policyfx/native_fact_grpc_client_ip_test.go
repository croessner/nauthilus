// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	authv1 "github.com/croessner/nauthilus/v4/api/auth/v1"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/handler/grpcauthority"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	policy "github.com/croessner/nauthilus/v4/server/policy"

	"google.golang.org/grpc/metadata"
)

// grpcPeerClientIPFixture mirrors the GeoIP environment binding behind selectable scheduler guards.
const grpcPeerClientIPFixture = `policy:
  namespaces:
    authn:
      condition_sets:
        networks:
          loopback_clients: [127.0.0.0/8, "::1"]
      providers:
        environment:
          kind: native
          module: geoip
          targets:
            - action: authenticate
            - action: lookup_identity
          produced_facts: [plugin.geoip.lookup_state]
          failure: indeterminate
          timeout: 500ms
      domain_plans:
        live:
          scheduler_guards:
            pre_auth_exempt_source:
              on_missing_attribute: run
              if:
                all:
                  - {attribute: nauthilus.request.client.ip.present, is: true}
                  - {attribute: nauthilus.request.client.ip.trusted, is: true}
                  - {attribute: nauthilus.request.client.ip, cidr_contains: "@network.loopback_clients"}
            pre_auth_without_client_ip:
              if: {attribute: nauthilus.request.client.ip.present, is: false}
          checkpoints:
            pre_auth:
              providers:
                - name: plugin_environment_geoip
                  use: authn/plugin.geoip.environment
                  actions: [authenticate, lookup_identity]
                  skip_if: [%s]
            auth_backend:
              providers:
                - {name: ldap_backend, use: authn/builtin/ldap_backend}
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/live
      default_policy: authn/standard_auth
    - namespace: authn
      action: lookup_identity
      schema: authn/lookup_identity/v1
      domain_plan: authn/live
      default_policy: authn/standard_auth
`

const (
	grpcPeerClientIPUsername = "push@example.test"
	grpcPeerPodAddress       = "172.20.3.17"
	grpcPeerAssertedAddress  = "198.51.100.7"
	grpcPeerExemptGuard      = "pre_auth_exempt_source"
)

type grpcPeerClientIPCase struct {
	name         string
	skipIf       string
	inputFact    string
	clientIP     string
	peer         net.Addr
	wantDecision authv1.AuthDecision
	wantCalls    int
	wantGeoIP    string
	wantClientIP grpcPeerClientIPObservation
}

// TestGRPCLookupIdentityWithoutClientIPGeoIPBindingInput reproduces the shadow tempfail of a no-auth gRPC
// identity lookup without client_ip. The loopback exemption guard reads the host-normalized client address,
// which falls back to the gRPC peer. A GeoIP binding that selects the caller-asserted input.auth.client_ip
// sees no address for the same request and fails closed; binding the host-normalized fact gives the guard
// and GeoIP one consistent address.
func TestGRPCLookupIdentityWithoutClientIPGeoIPBindingInput(t *testing.T) {
	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	for _, testCase := range grpcPeerClientIPCases() {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &grpcPeerGeoIPProvider{inputFact: testCase.inputFact}
			client := newGRPCPeerClientIPClient(t, provider, testCase.skipIf, testCase.peer)

			response, err := client.LookupIdentity(grpcPeerClientIPRequestContext(t), &authv1.LookupIdentityRequest{
				Username: grpcPeerClientIPUsername,
				ClientIp: testCase.clientIP,
				Protocol: "jmap",
				Method:   "recipient_lookup",
			})
			if err != nil {
				t.Fatalf("LookupIdentity() error = %v", err)
			}

			if response.GetDecision() != testCase.wantDecision {
				t.Fatalf("LookupIdentity() decision = %s, want %s (GeoIP observations %#v)",
					response.GetDecision(), testCase.wantDecision, provider.snapshot())
			}

			provider.assertCalls(t, testCase.wantCalls, testCase.wantGeoIP, testCase.wantClientIP)
		})
	}
}

// grpcPeerClientIPCases covers both binding inputs for loopback, pod-network, and address-less peers.
//
// A GeoIP binding requires its input; an address-less request stays fail-closed unless the plan
// explicitly skips the provider with a scheduler guard on nauthilus.request.client.ip.present.
func grpcPeerClientIPCases() []grpcPeerClientIPCase {
	loopback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}
	pod := &net.TCPAddr{IP: net.ParseIP(grpcPeerPodAddress), Port: 41000}
	unix := &net.UnixAddr{Name: "/run/nauthilus/grpc.sock", Net: "unix"}
	podFacts := grpcPeerClientIPObservation{ip: grpcPeerPodAddress, present: true, trusted: true}
	ok := authv1.AuthDecision_AUTH_DECISION_OK
	tempFail := authv1.AuthDecision_AUTH_DECISION_TEMPFAIL

	return []grpcPeerClientIPCase{
		{name: "caller fact loopback peer is exempt", inputFact: policy.AuthnFactClientIP, peer: loopback, wantDecision: ok},
		{
			name: "caller fact pod peer has no GeoIP input", inputFact: policy.AuthnFactClientIP, peer: pod,
			wantDecision: tempFail, wantCalls: 1, wantClientIP: podFacts,
		},
		{name: "host fact loopback peer is exempt", inputFact: policy.AuthnFactRequestClientIP, peer: loopback, wantDecision: ok},
		{
			name: "host fact pod peer reaches GeoIP", inputFact: policy.AuthnFactRequestClientIP, peer: pod,
			wantDecision: ok, wantCalls: 1, wantGeoIP: grpcPeerPodAddress, wantClientIP: podFacts,
		},
		{
			name: "host fact keeps caller asserted address untrusted", inputFact: policy.AuthnFactRequestClientIP,
			clientIP: grpcPeerAssertedAddress, peer: pod, wantDecision: ok, wantCalls: 1, wantGeoIP: grpcPeerAssertedAddress,
			wantClientIP: grpcPeerClientIPObservation{ip: grpcPeerAssertedAddress, present: true},
		},
		{
			name: "host fact unix socket peer fails closed", inputFact: policy.AuthnFactRequestClientIP,
			peer: unix, wantDecision: tempFail, wantCalls: 1,
		},
		{
			name: "host fact unix socket peer skipped by address guard", inputFact: policy.AuthnFactRequestClientIP,
			skipIf: grpcPeerExemptGuard + ", pre_auth_without_client_ip", peer: unix, wantDecision: ok,
		},
	}
}

// grpcPeerClientIPRequestContext presents the dedicated backchannel Basic credential.
func grpcPeerClientIPRequestContext(t *testing.T) context.Context {
	t.Helper()

	credential := base64.StdEncoding.EncodeToString([]byte(productionTransportBackchannelUser + ":" + productionTransportBackchannelPassword))

	return metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Basic "+credential))
}

// newGRPCPeerClientIPClient serves the production authority stack whose accepted connections report one peer.
func newGRPCPeerClientIPClient(
	t *testing.T,
	provider *grpcPeerGeoIPProvider,
	skipIf string,
	remote net.Addr,
) authv1.AuthServiceClient {
	t.Helper()

	if skipIf == "" {
		skipIf = grpcPeerExemptGuard
	}

	configured, state := nativeGenerationCandidateFromFixture(
		t, fmt.Sprintf(grpcPeerClientIPFixture, skipIf), "geoip", grpcPeerGeoIPOpener{provider: provider},
	)
	enableGRPCAuthorityBackchannel(configured)

	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	application := newNativeAuthApplication(t, configured, runtime.service)

	connection := serveProductionGRPCAuthority(t, grpcauthority.ServerDeps{
		Cfg:           configured,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthService:   application,
		PolicyService: runtime.service,
	}, remote)

	return authv1.NewAuthServiceClient(connection)
}

// grpcPeerClientIPObservation stores the host-normalized client-IP facts one provider call received.
type grpcPeerClientIPObservation struct {
	ip      string
	present bool
	trusted bool
}

// grpcPeerGeoIPCall stores everything one GeoIP-shaped Collect call received.
type grpcPeerGeoIPCall struct {
	geoIPInput string
	clientIP   grpcPeerClientIPObservation
}

// grpcPeerGeoIPProvider mirrors the GeoIP decision binding: it requires one configured string client-IP fact.
type grpcPeerGeoIPProvider struct {
	calls     []grpcPeerGeoIPCall
	inputFact string
	mu        sync.Mutex
}

// Descriptor declares the GeoIP environment component for both authn operations.
func (p *grpcPeerGeoIPProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{
		Namespace: policy.AuthnNamespace, Name: "environment", Timeout: pluginapi.MaximumDecisionFactProviderTimeout,
		Targets: []pluginapi.DecisionTargetSelector{
			{Namespace: policy.AuthnNamespace, Action: string(policy.OperationAuthenticate)},
			{Namespace: policy.AuthnNamespace, Action: string(policy.OperationLookupIdentity)},
		},
		Inputs: []pluginapi.DecisionFactInputDescriptor{{
			ID: p.inputFact, Category: pluginapi.DecisionFactCategoryEnvironment,
			Kind: pluginapi.DecisionValueKindString,
		}},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{{
			Name: "lookup_state", Category: pluginapi.DecisionFactCategoryEnvironment,
			Kind: pluginapi.DecisionValueKindString, MaxLength: 64,
		}},
	}
}

// Collect records the observed facts and rejects a missing client IP exactly like the GeoIP plugin.
func (p *grpcPeerGeoIPProvider) Collect(
	_ context.Context,
	request pluginapi.DecisionFactRequest,
) (pluginapi.DecisionFactResult, error) {
	call := grpcPeerGeoIPCall{}

	for _, fact := range request.Facts() {
		if fact.ID() == p.inputFact && fact.Category() == pluginapi.DecisionFactCategoryEnvironment {
			call.geoIPInput, _ = fact.Value().StringValue()
		}

		switch fact.ID() {
		case policy.AuthnFactRequestClientIP:
			call.clientIP.ip, _ = fact.Value().StringValue()
		case policy.AuthnFactRequestClientIPPresent:
			call.clientIP.present, _ = fact.Value().Boolean()
		case policy.AuthnFactRequestClientIPTrusted:
			call.clientIP.trusted, _ = fact.Value().Boolean()
		}
	}

	p.mu.Lock()
	p.calls = append(p.calls, call)
	p.mu.Unlock()

	if net.ParseIP(call.geoIPInput) == nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
	}

	state := "matched"

	value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &state})
	if err != nil {
		return pluginapi.DecisionFactResult{}, err
	}

	return pluginapi.DecisionFactResult{Facts: []pluginapi.DecisionFactOutput{{Name: "lookup_state", Value: value}}}, nil
}

// snapshot returns a detached copy of all recorded calls.
func (p *grpcPeerGeoIPProvider) snapshot() []grpcPeerGeoIPCall {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]grpcPeerGeoIPCall(nil), p.calls...)
}

// assertCalls verifies the scheduling decision and the exact client-IP facts of every provider call.
func (p *grpcPeerGeoIPProvider) assertCalls(
	t *testing.T,
	want int,
	wantGeoIP string,
	wantClientIP grpcPeerClientIPObservation,
) {
	t.Helper()

	calls := p.snapshot()
	if len(calls) != want {
		t.Fatalf("GeoIP calls = %#v, want %d", calls, want)
	}

	for _, call := range calls {
		if call.geoIPInput != wantGeoIP || call.clientIP != wantClientIP {
			t.Fatalf("GeoIP call = %#v, want input %q and client facts %#v", call, wantGeoIP, wantClientIP)
		}
	}
}

type grpcPeerGeoIPOpener struct {
	provider *grpcPeerGeoIPProvider
}

// Open returns the hermetic GeoIP-shaped plugin handle.
func (o grpcPeerGeoIPOpener) Open(string) (pluginloader.PluginHandle, error) {
	return grpcPeerGeoIPHandle(o), nil
}

type grpcPeerGeoIPHandle struct {
	provider *grpcPeerGeoIPProvider
}

// Lookup returns the exact required public factory symbol.
func (h grpcPeerGeoIPHandle) Lookup(symbol string) (any, error) {
	if symbol != "NauthilusPlugin" {
		return nil, errors.New("unexpected plugin symbol")
	}

	return func() (pluginapi.Plugin, error) { return grpcPeerGeoIPPlugin(h), nil }, nil
}

type grpcPeerGeoIPPlugin struct {
	provider *grpcPeerGeoIPProvider
}

// Metadata returns one compatible test plugin contract.
func (grpcPeerGeoIPPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: "geoip-client-ip-test", Version: "1.0.0", APIVersion: pluginapi.APIVersion}
}

// Register publishes only the GeoIP-shaped decision fact provider.
func (p grpcPeerGeoIPPlugin) Register(registrar pluginapi.Registrar) error {
	decisionRegistrar, ok := registrar.(pluginapi.DecisionRegistrar)
	if !ok {
		return errors.New("registrar does not support generic decision fact providers")
	}

	return decisionRegistrar.RegisterDecisionFactProvider(p.provider)
}
