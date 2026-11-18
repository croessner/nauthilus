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

package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

const (
	headerForwardedFor   = "X-Forwarded-For"
	headerForwardedProto = "X-Forwarded-Proto"
	headerForwardedHost  = "X-Forwarded-Host"
	headerOrigin         = "Origin"
	schemeHTTP           = "http"
)

// transportKey carries the derived transport facts of one request.
type transportKey struct{}

// transport is what the guard established about one request.
type transport struct {
	clientIP netip.Addr
}

// clientIPOf returns the client IP the guard derived, or the zero address.
func clientIPOf(ctx context.Context) netip.Addr {
	if facts, ok := ctx.Value(transportKey{}).(transport); ok {
		return facts.clientIP
	}

	return netip.Addr{}
}

// guard enforces the transport boundary before anything else: TLS terminated by a trusted proxy (or direct loopback
// for a plain-http loopback resource), an allowed Host, no foreign browser Origin, and only the methods the
// endpoint serves. It never sets CORS headers; browser clients are not supported.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		facts, reason := s.inspectTransport(request)
		if reason != "" {
			s.reject(writer, request, http.StatusForbidden, resultRejected, reason)

			return
		}

		switch request.Method {
		case http.MethodGet, http.MethodPost, http.MethodHead, http.MethodDelete:
		default:
			s.reject(writer, request, http.StatusMethodNotAllowed, resultRejected, "method_not_allowed")

			return
		}

		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), transportKey{}, facts)))
	})
}

// inspectTransport derives the client IP, scheme, and host and returns a rejection reason or "".
func (s *Server) inspectTransport(request *http.Request) (transport, string) {
	remote, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil {
		return transport{}, "remote_address"
	}

	facts, scheme, host, reason := s.peerTransport(request, remote.Addr().Unmap())
	if reason != "" {
		return transport{}, reason
	}

	if !strings.EqualFold(scheme, s.resource.Scheme) {
		return transport{}, "scheme_mismatch"
	}

	if !slices.ContainsFunc(s.hosts, func(allowed string) bool { return strings.EqualFold(allowed, host) }) {
		return transport{}, "host_not_allowed"
	}

	origins := request.Header.Values(headerOrigin)
	if len(origins) > 1 || (len(origins) == 1 && !slices.Contains(s.origins, origins[0])) {
		return transport{}, "origin_not_allowed"
	}

	return facts, ""
}

// peerTransport derives client IP, scheme, and host from a trusted proxy's headers or from a direct loopback peer,
// and returns a rejection reason for any other peer.
func (s *Server) peerTransport(request *http.Request, peer netip.Addr) (transport, string, string, string) {
	if !s.trusted(peer) {
		if s.directLoopback(peer) {
			return transport{clientIP: peer}, schemeHTTP, request.Host, ""
		}

		return transport{}, "", "", "untrusted_transport"
	}

	client, ok := s.forwardedClient(request.Header.Values(headerForwardedFor))
	if !ok {
		return transport{}, "", "", "forwarded_for_missing"
	}

	scheme, host := lastListValue(request.Header.Values(headerForwardedProto)), request.Host

	if forwardedHost := lastListValue(request.Header.Values(headerForwardedHost)); forwardedHost != "" {
		host = forwardedHost
	}

	if scheme == "" && s.directLoopback(peer) {
		scheme = schemeHTTP
	}

	return transport{clientIP: client}, scheme, host, ""
}

// directLoopback reports whether a peer may reach a plain-http loopback resource without a proxy.
func (s *Server) directLoopback(peer netip.Addr) bool {
	return peer.IsLoopback() && s.resource.Scheme == schemeHTTP && isLoopbackResource(s.resource.Hostname())
}

// trusted reports whether a peer is a configured trusted proxy.
func (s *Server) trusted(peer netip.Addr) bool {
	return slices.ContainsFunc(s.proxies, func(prefix netip.Prefix) bool { return prefix.Contains(peer) })
}

// forwardedClient returns the right-most X-Forwarded-For hop that is not a trusted proxy. Hops left of it are
// client-supplied and never decide the client IP. A hop may carry a port. A chain without such a hop, or with an
// unparsable hop before it is found, has no trustworthy client IP and is refused, so clients never collapse into the
// proxy's own address.
func (s *Server) forwardedClient(values []string) (netip.Addr, bool) {
	hops := forwardedHops(values)

	for index := len(hops) - 1; index >= 0; index-- {
		addr, ok := parseHop(hops[index])
		if !ok {
			return netip.Addr{}, false
		}

		if !s.trusted(addr) {
			return addr, true
		}
	}

	return netip.Addr{}, false
}

// parseHop parses one X-Forwarded-For hop: an IP address, optionally with a port ("ip:port" or "[ipv6]:port").
func parseHop(hop string) (netip.Addr, bool) {
	hop = strings.TrimSpace(hop)

	if addr, err := netip.ParseAddr(hop); err == nil {
		return addr.Unmap(), true
	}

	if addrPort, err := netip.ParseAddrPort(hop); err == nil {
		return addrPort.Addr().Unmap(), true
	}

	return netip.Addr{}, false
}

// forwardedHops splits every X-Forwarded-For header into its comma-separated hops in order.
func forwardedHops(values []string) []string {
	var hops []string

	for _, value := range values {
		hops = append(hops, strings.Split(value, ",")...)
	}

	return hops
}

// lastListValue returns the right-most comma-separated value of a header, set by the nearest proxy.
func lastListValue(values []string) string {
	hops := forwardedHops(values)
	if len(hops) == 0 {
		return ""
	}

	return strings.TrimSpace(hops[len(hops)-1])
}

// isLoopbackResource reports whether a resource host is localhost or a loopback IP.
func isLoopbackResource(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)

	return err == nil && addr.IsLoopback()
}

// reject answers a refused request with a short JSON error and records it.
func (s *Server) reject(writer http.ResponseWriter, request *http.Request, status int, result string, reason string) {
	s.record(request.Context(), accessRecord{result: result, reason: reason, status: status})
	writeJSONError(writer, status, reason)
}

// writeJSONError writes a minimal JSON error body.
func writeJSONError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": code})
}
