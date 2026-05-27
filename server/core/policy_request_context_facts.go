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
	"net"
	"net/netip"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	requestPolicyClientIPSourceDirectPeer    = "direct_peer"
	requestPolicyClientIPSourceProxyProtocol = "proxy_protocol"
	requestPolicyClientIPSourceTrustedProxy  = "trusted_proxy_header"
	requestPolicyClientIPSourceGRPCPeer      = "grpc_peer"
	requestPolicyClientIPSourceMetadata      = "metadata"
	requestPolicyClientIPSourceUnknown       = "unknown"

	requestPolicyTransportHTTP    = "http"
	requestPolicyTransportGRPC    = "grpc"
	requestPolicyTransportIDP     = "idp"
	requestPolicyTransportUnknown = "unknown"

	requestPolicyListenerHTTP          = "http"
	requestPolicyListenerIDP           = "http.idp"
	requestPolicyListenerGRPCAuthority = "grpc.authority"

	requestPolicyInitiatorExternalUser    = "external_user"
	requestPolicyInitiatorInternalService = "internal_service"
	requestPolicyInitiatorUnknown         = "unknown"
)

type requestGRPCMethodContextKey struct{}

type requestIPFacts struct {
	source  string
	addr    netip.Addr
	present bool
}

type requestClientIPFacts struct {
	requestIPFacts
	trusted bool
}

type requestLocalEndpointFacts struct {
	ip          requestIPFacts
	port        string
	portPresent bool
}

// ContextWithGRPCMethod stores a server-derived gRPC method for request policy facts.
func ContextWithGRPCMethod(ctx context.Context, method string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	method = normalizeGRPCMethod(method)
	if method == "" {
		return ctx
	}

	return context.WithValue(ctx, requestGRPCMethodContextKey{}, method)
}

func (a *AuthState) recordRequestContextFacts(
	policyCtx *policycollection.DecisionContext,
	ctx *gin.Context,
	operation policy.Operation,
) {
	if policyCtx == nil {
		return
	}

	clientIP := a.requestClientIPFacts(ctx)
	callerIP := a.requestCallerIPFacts(ctx)
	localEndpoint := a.requestLocalEndpointFacts()
	transportKind := a.requestTransportKind()

	clientIP.record(policyCtx, operation)
	callerIP.record(
		policyCtx,
		operation,
		policy.AttributeRequestCallerIP,
		policy.AttributeRequestCallerIPPresent,
		policy.AttributeRequestCallerIPSource,
	)
	localEndpoint.record(policyCtx, operation)
	policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestTransportKind, policy.StagePreAuth, operation, transportKind))
	policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestListenerName, policy.StagePreAuth, operation, a.requestListenerName()))
	policyCtx.RecordAttribute(policycollection.BoolAttribute(policy.AttributeRequestConnectionTLS, policy.StagePreAuth, operation, requestConnectionTLS(ctx), nil))
	policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestInitiatorKind, policy.StagePreAuth, operation, a.requestInitiatorKind()))

	if route := normalizedHTTPRoute(ctx); route != "" {
		policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestHTTPRoute, policy.StagePreAuth, operation, route))
	}

	if method := grpcMethodFromContext(contextFromGin(ctx)); method != "" && transportKind == requestPolicyTransportGRPC {
		policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestGRPCMethod, policy.StagePreAuth, operation, method))
	}

	if clientID := strings.TrimSpace(a.Request.OIDCCID); clientID != "" {
		policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestIDPClientID, policy.StagePreAuth, operation, clientID))
	}

	if entityID := strings.TrimSpace(a.Request.SAMLEntityID); entityID != "" {
		policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestSAMLServiceProviderID, policy.StagePreAuth, operation, entityID))
	}
}

// record stores the request IP fact with a fail-closed presence marker.
func (f requestIPFacts) record(
	policyCtx *policycollection.DecisionContext,
	operation policy.Operation,
	ipAttribute string,
	presentAttribute string,
	sourceAttribute string,
) {
	if f.source == "" {
		f.source = requestPolicyClientIPSourceUnknown
	}

	if f.present {
		policyCtx.RecordAttribute(policycollection.IPAttribute(ipAttribute, policy.StagePreAuth, operation, f.addr))
	}

	policyCtx.RecordAttribute(policycollection.BoolAttribute(presentAttribute, policy.StagePreAuth, operation, f.present, nil))

	if sourceAttribute != "" {
		policyCtx.RecordAttribute(policycollection.StringAttribute(sourceAttribute, policy.StagePreAuth, operation, f.source))
	}
}

// record stores client-IP facts, including source trust metadata.
func (f requestClientIPFacts) record(policyCtx *policycollection.DecisionContext, operation policy.Operation) {
	f.requestIPFacts.record(
		policyCtx,
		operation,
		policy.AttributeRequestClientIP,
		policy.AttributeRequestClientIPPresent,
		policy.AttributeRequestClientIPSource,
	)
	policyCtx.RecordAttribute(policycollection.BoolAttribute(policy.AttributeRequestClientIPTrusted, policy.StagePreAuth, operation, f.trusted, nil))
}

// record stores the caller-supplied local endpoint facts.
func (f requestLocalEndpointFacts) record(policyCtx *policycollection.DecisionContext, operation policy.Operation) {
	f.ip.record(
		policyCtx,
		operation,
		policy.AttributeRequestLocalIP,
		policy.AttributeRequestLocalIPPresent,
		"",
	)

	if f.portPresent {
		policyCtx.RecordAttribute(policycollection.StringAttribute(policy.AttributeRequestLocalPort, policy.StagePreAuth, operation, f.port))
	}

	policyCtx.RecordAttribute(policycollection.BoolAttribute(policy.AttributeRequestLocalPortPresent, policy.StagePreAuth, operation, f.portPresent, nil))
}

// requestClientIPFacts resolves the end-client IP and labels whether that source is trusted.
func (a *AuthState) requestClientIPFacts(ctx *gin.Context) requestClientIPFacts {
	source := requestPolicyClientIPSourceUnknown
	if a == nil {
		return requestClientIPFacts{requestIPFacts: requestIPFacts{source: source}}
	}

	candidate := strings.TrimSpace(a.Request.ClientIP)

	if candidate == "" && a.Request.Service == definitions.ServGRPC {
		candidate = grpcPeerIP(contextFromGin(ctx))
		source = requestPolicyClientIPSourceGRPCPeer
	}

	if candidate == "" {
		return requestClientIPFacts{requestIPFacts: requestIPFacts{source: source}}
	}

	facts := parseRequestIPFacts(candidate, source)
	if !facts.present {
		return requestClientIPFacts{requestIPFacts: facts}
	}

	source, trusted := a.requestClientIPTrust(ctx, candidate, source)
	facts.source = source

	return requestClientIPFacts{
		requestIPFacts: facts,
		trusted:        trusted,
	}
}

// requestCallerIPFacts resolves the peer that connected to Nauthilus.
func (a *AuthState) requestCallerIPFacts(ctx *gin.Context) requestIPFacts {
	if a != nil && a.Request.Service == definitions.ServGRPC {
		return requestGRPCCallerIPFacts(ctx)
	}

	return parseRequestIPFacts(directPeerIP(ctx), requestPolicyClientIPSourceDirectPeer)
}

// requestGRPCCallerIPFacts prefers gRPC peer metadata and falls back to the direct peer.
func requestGRPCCallerIPFacts(ctx *gin.Context) requestIPFacts {
	candidate := grpcPeerIP(contextFromGin(ctx))
	if candidate != "" {
		return parseRequestIPFacts(candidate, requestPolicyClientIPSourceGRPCPeer)
	}

	return parseRequestIPFacts(directPeerIP(ctx), requestPolicyClientIPSourceDirectPeer)
}

// requestLocalEndpointFacts parses the local endpoint values supplied by the caller.
func (a *AuthState) requestLocalEndpointFacts() requestLocalEndpointFacts {
	if a == nil {
		return requestLocalEndpointFacts{}
	}

	port := strings.TrimSpace(a.Request.XPort)

	return requestLocalEndpointFacts{
		ip:          parseRequestIPFacts(a.Request.XLocalIP, requestPolicyClientIPSourceUnknown),
		port:        port,
		portPresent: port != "",
	}
}

// parseRequestIPFacts keeps invalid or empty IP values absent while preserving source context.
func parseRequestIPFacts(candidate string, source string) requestIPFacts {
	source = strings.TrimSpace(source)
	if source == "" {
		source = requestPolicyClientIPSourceUnknown
	}

	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return requestIPFacts{source: source}
	}

	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return requestIPFacts{source: source}
	}

	return requestIPFacts{
		source:  source,
		addr:    addr,
		present: true,
	}
}

// requestClientIPTrust classifies whether the selected client IP source can be trusted.
func (a *AuthState) requestClientIPTrust(ctx *gin.Context, candidate string, fallbackSource string) (string, bool) {
	if a == nil {
		return requestPolicyClientIPSourceUnknown, false
	}

	if a.Request.Service == definitions.ServGRPC {
		if sameIP(candidate, grpcPeerIP(contextFromGin(ctx))) {
			return requestPolicyClientIPSourceGRPCPeer, true
		}

		return requestPolicyClientIPSourceMetadata, false
	}

	if a.configuredClientIPHeaderMatches(ctx, candidate) {
		if a.directPeerIsTrustedProxy(ctx) {
			return requestPolicyClientIPSourceTrustedProxy, true
		}

		return requestPolicyClientIPSourceMetadata, false
	}

	directPeer := directPeerIP(ctx)
	if sameIP(candidate, directPeer) {
		if a.proxyProtocolEnabled() {
			return requestPolicyClientIPSourceProxyProtocol, true
		}

		return requestPolicyClientIPSourceDirectPeer, true
	}

	if fallbackSource == "" {
		fallbackSource = requestPolicyClientIPSourceMetadata
	}

	return fallbackSource, false
}

func (a *AuthState) configuredClientIPHeaderMatches(ctx *gin.Context, candidate string) bool {
	if a == nil || a.Cfg() == nil {
		return false
	}

	header := strings.TrimSpace(a.Cfg().GetClientIP())
	if header == "" {
		return false
	}

	return headerIPMatches(getDecodedHeader(ctx, header), candidate)
}

func (a *AuthState) directPeerIsTrustedProxy(ctx *gin.Context) bool {
	if a == nil || a.Cfg() == nil || a.Cfg().GetServer() == nil {
		return false
	}

	peerIP := directPeerIP(ctx)
	if peerIP == "" {
		return false
	}

	return util.IsInNetworkWithCfg(contextFromGin(ctx), a.Cfg(), a.Logger(), a.Cfg().GetServer().GetTrustedProxies(), a.Runtime.GUID, peerIP)
}

func (a *AuthState) proxyProtocolEnabled() bool {
	return a != nil && a.Cfg() != nil && a.Cfg().GetServer() != nil && a.Cfg().GetServer().IsHAproxyProtocolEnabled()
}

func headerIPMatches(headerValue string, candidate string) bool {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return false
	}

	for part := range strings.SplitSeq(headerValue, ",") {
		if sameIP(strings.TrimSpace(part), candidate) {
			return true
		}
	}

	return false
}

func sameIP(left string, right string) bool {
	leftAddr, err := netip.ParseAddr(strings.TrimSpace(left))
	if err != nil {
		return false
	}

	rightAddr, err := netip.ParseAddr(strings.TrimSpace(right))
	if err != nil {
		return false
	}

	return leftAddr == rightAddr
}

func directPeerIP(ctx *gin.Context) string {
	if ctx == nil || ctx.Request == nil {
		return ""
	}

	remoteAddr := strings.TrimSpace(ctx.Request.RemoteAddr)
	if remoteAddr == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return strings.TrimSpace(host)
	}

	return remoteAddr
}

func grpcPeerIP(ctx context.Context) string {
	requestPeer, ok := peer.FromContext(ctx)
	if !ok || requestPeer.Addr == nil {
		return ""
	}

	if tcpAddr, ok := requestPeer.Addr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		return tcpAddr.IP.String()
	}

	host, _, err := net.SplitHostPort(requestPeer.Addr.String())
	if err == nil {
		return strings.TrimSpace(host)
	}

	return strings.TrimSpace(requestPeer.Addr.String())
}

func (a *AuthState) requestTransportKind() string {
	if a == nil {
		return requestPolicyTransportUnknown
	}

	switch a.Request.Service {
	case definitions.ServGRPC:
		return requestPolicyTransportGRPC
	case definitions.ServIdP:
		return requestPolicyTransportIDP
	case definitions.ServBasic, definitions.ServCBOR, definitions.ServHeader, definitions.ServJSON, definitions.ServNginx:
		return requestPolicyTransportHTTP
	default:
		return requestPolicyTransportUnknown
	}
}

func (a *AuthState) requestListenerName() string {
	if a == nil {
		return ""
	}

	switch a.Request.Service {
	case definitions.ServGRPC:
		return requestPolicyListenerGRPCAuthority
	case definitions.ServIdP:
		return requestPolicyListenerIDP
	case definitions.ServBasic, definitions.ServCBOR, definitions.ServHeader, definitions.ServJSON, definitions.ServNginx:
		return requestPolicyListenerHTTP
	default:
		return ""
	}
}

func (a *AuthState) requestInitiatorKind() string {
	if a == nil {
		return requestPolicyInitiatorUnknown
	}

	if a.Request.Service == definitions.ServGRPC {
		return requestPolicyInitiatorInternalService
	}

	return requestPolicyInitiatorExternalUser
}

func requestConnectionTLS(ctx *gin.Context) bool {
	if ctx == nil || ctx.Request == nil {
		return false
	}

	if ctx.Request.TLS != nil {
		return true
	}

	requestPeer, ok := peer.FromContext(ctx.Request.Context())
	if !ok {
		return false
	}

	_, ok = requestPeer.AuthInfo.(credentials.TLSInfo)

	return ok
}

func normalizedHTTPRoute(ctx *gin.Context) string {
	if ctx == nil {
		return ""
	}

	return strings.TrimSpace(ctx.FullPath())
}

func grpcMethodFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	method, _ := ctx.Value(requestGRPCMethodContextKey{}).(string)

	return normalizeGRPCMethod(method)
}

func normalizeGRPCMethod(method string) string {
	method = strings.TrimSpace(method)
	if method == "" || !strings.HasPrefix(method, "/") {
		return ""
	}

	return method
}
