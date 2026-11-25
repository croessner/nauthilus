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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/jsonstrict"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
	"github.com/croessner/nauthilus/v4/server/supportapi"
)

const (
	methodToolsCall = "tools/call"
	headerMCPMethod = "Mcp-Method"
	headerMCPName   = "Mcp-Name"
)

// rpcEnvelope is the part of a JSON-RPC message the endpoint reads before the SDK.
type rpcEnvelope struct {
	method string
	name   string
}

// envelopeMembers are the member names the endpoint and the SDK both read; the SDK matches them case-sensitively.
var envelopeMembers = []string{"jsonrpc", "id", "method", "params"}

// paramsMembers are the parameter names the endpoint reads before the SDK.
var paramsMembers = []string{"name", "arguments", "_meta"}

// parseEnvelope reads method and tool name with exact, case-sensitive member names like the SDK, and refuses any
// case variant of a member both parsers read, so the inspection can never see another message than the SDK.
func parseEnvelope(body []byte) (rpcEnvelope, bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal(body, &members) != nil || hasCaseVariant(members, envelopeMembers) {
		return rpcEnvelope{}, false
	}

	var envelope rpcEnvelope
	if raw, ok := members["method"]; ok && json.Unmarshal(raw, &envelope.method) != nil {
		return rpcEnvelope{}, false
	}

	raw, ok := members["params"]
	if !ok || envelope.method != methodToolsCall {
		return envelope, true
	}

	var params map[string]json.RawMessage
	if json.Unmarshal(raw, &params) != nil || hasCaseVariant(params, paramsMembers) {
		return rpcEnvelope{}, false
	}

	if rawName, named := params["name"]; named && json.Unmarshal(rawName, &envelope.name) != nil {
		return rpcEnvelope{}, false
	}

	return envelope, true
}

// hasCaseVariant reports whether members contain a name that equals one of names only case-insensitively.
func hasCaseVariant(members map[string]json.RawMessage, names []string) bool {
	for member := range members {
		for _, name := range names {
			if member != name && strings.EqualFold(member, name) {
				return true
			}
		}
	}

	return false
}

// requestIDBytes returns the length of the JSON-RPC id of a body as written, which the response repeats; 0 without one.
func requestIDBytes(body []byte) int {
	var members map[string]json.RawMessage
	if json.Unmarshal(body, &members) != nil {
		return 0
	}

	return len(bytes.TrimSpace(members["id"]))
}

// inspectBody reads the bounded body once and refuses what the SDK must never see: oversized bodies, duplicate
// member names, batches, headers that disagree with the body (2026-07-28 Mcp-Method/Mcp-Name), and a tool call whose
// scopes the token lacks (403 insufficient_scope, so the client can step up). The service check stays authoritative.
func (s *Server) inspectBody(writer http.ResponseWriter, request *http.Request, credential supportaccess.VerifiedCredential) (int, bool) {
	if request.Method != http.MethodPost {
		return 0, true
	}

	body, err := io.ReadAll(io.LimitReader(request.Body, s.maxRequest+1))
	if err != nil {
		s.reject(writer, request, http.StatusBadRequest, resultRejected, "unreadable_body")

		return 0, false
	}

	if int64(len(body)) > s.maxRequest {
		s.reject(writer, request, http.StatusRequestEntityTooLarge, resultRejected, "body_too_large")

		return 0, false
	}

	if reason := envelopeDefect(request, body); reason != "" {
		s.reject(writer, request, http.StatusBadRequest, resultRejected, reason)

		return 0, false
	}

	if scopes, refused := missingToolScopes(body, credential); refused {
		s.challenge(writer, request, http.StatusForbidden, errorInsufficientScope, scopes, "insufficient_scope")

		return 0, false
	}

	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))

	return requestIDBytes(body), true
}

// envelopeDefect returns why a body is refused before the SDK, or "". A body that is not a valid JSON object is left
// to the SDK, which answers it with a JSON-RPC error.
func envelopeDefect(request *http.Request, body []byte) string {
	trimmed := bytes.TrimSpace(body)

	switch {
	case len(trimmed) > 0 && trimmed[0] == '[':
		return "batch_not_supported"
	case jsonstrict.HasDuplicateNames(trimmed):
		return "duplicate_json_names"
	case len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed):
		return ""
	}

	envelope, ok := parseEnvelope(trimmed)
	if !ok {
		return "ambiguous_json_rpc_envelope"
	}

	return headerDefect(request, envelope)
}

// headerDefect returns why the 2026-07-28 Mcp-Method / Mcp-Name headers disagree with the body, or "".
func headerDefect(request *http.Request, envelope rpcEnvelope) string {
	if method := request.Header.Get(headerMCPMethod); method != "" && method != envelope.method {
		return "mcp_method_mismatch"
	}

	if name := request.Header.Get(headerMCPName); envelope.method == methodToolsCall && name != "" && name != envelope.name {
		return "mcp_name_mismatch"
	}

	return ""
}

// missingToolScopes reports whether a tools/call names a known tool the credential has no scope for; it returns the
// scopes that tool needs. The envelope was already validated by envelopeDefect.
func missingToolScopes(body []byte, credential supportaccess.VerifiedCredential) ([]string, bool) {
	envelope, ok := parseEnvelope(bytes.TrimSpace(body))
	if !ok || envelope.method != methodToolsCall {
		return nil, false
	}

	operation, known := supportapi.Lookup(envelope.name)
	if !known {
		return nil, false
	}

	if slices.ContainsFunc(operation.Scopes, credential.HasScope) {
		return nil, false
	}

	return operation.Scopes, true
}
