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
	"errors"
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
	"github.com/croessner/nauthilus/v4/server/supportapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// errUnauthenticated is a protocol error for a tool call without verified facts; the bearer gate prevents it.
var errUnauthenticated = errors.New("unauthenticated tool call")

// newSDKServer registers every support operation as a read-only tool. All tools are listed to every caller; the
// service decides authorization per call.
func (s *Server) newSDKServer() (*mcp.Server, error) {
	sdkServer := mcp.NewServer(&mcp.Implementation{Name: implementationName, Title: implementationTitle, Version: s.deps.Version},
		&mcp.ServerOptions{Instructions: serverInstructions, SupportedProtocolVersions: supportedProtocolVersions,
			Logger: s.logger()})

	closedWorld, nonDestructive := false, false

	for _, operation := range supportapi.Operations() {
		schema, err := operation.InputSchema()
		if err != nil {
			return nil, err
		}

		sdkServer.AddTool(&mcp.Tool{Name: operation.Name, Title: operation.Title, Description: operation.ModelDescription(),
			InputSchema: schema, Annotations: &mcp.ToolAnnotations{Title: operation.Title, ReadOnlyHint: true,
				IdempotentHint: true, DestructiveHint: &nonDestructive, OpenWorldHint: &closedWorld}},
			s.toolHandler(operation))
	}

	return sdkServer, nil
}

// toolHandler executes one operation with the verified credential under the call budget. Legacy-era calls run on
// the stateless session context, so the HTTP request context is merged in to stop work for a gone client.
func (s *Server) toolHandler(operation supportapi.Operation) mcp.ToolHandler {
	return func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		credential, requestCtx, ok := verifiedFacts(request)
		if !ok {
			return nil, errUnauthenticated
		}

		ctx, stop := mergeCancellation(ctx, requestCtx)
		defer stop()

		ctx, cancel := context.WithTimeout(ctx, s.timeout)
		defer cancel()

		arguments := []byte(request.Params.Arguments)
		if len(arguments) == 0 {
			arguments = []byte("{}")
		}

		response := s.deps.Services.Execute(ctx, operation, credential, arguments)
		if int64(2*len(response.Body)) > s.maxResponse {
			response = supportapi.ResponseTooLarge(operation)
		}

		s.recordTool(requestCtx, operation.Name, credential, response)

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(response.Body)}},
			StructuredContent: json.RawMessage(response.Body), IsError: response.IsError()}, nil
	}
}

// verifiedFacts returns the credential and the HTTP request context the bearer gate attached to the call.
func verifiedFacts(request *mcp.CallToolRequest) (supportaccess.VerifiedCredential, context.Context, bool) {
	if request == nil || request.Extra == nil || request.Extra.TokenInfo == nil {
		return supportaccess.VerifiedCredential{}, nil, false
	}

	credential, ok := request.Extra.TokenInfo.Extra[extraCredential].(supportaccess.VerifiedCredential)
	if !ok || !credential.Verified() {
		return supportaccess.VerifiedCredential{}, nil, false
	}

	requestCtx, _ := request.Extra.TokenInfo.Extra[extraRequestContext].(context.Context)

	return credential, requestCtx, true
}

// mergeCancellation cancels ctx when other ends as well; stop releases the link.
func mergeCancellation(ctx context.Context, other context.Context) (context.Context, func()) {
	if other == nil {
		return ctx, func() {}
	}

	merged, cancel := context.WithCancelCause(ctx)
	unlink := context.AfterFunc(other, func() { cancel(context.Cause(other)) })

	return merged, func() {
		unlink()
		cancel(nil)
	}
}

// recordTool writes the transport record of one tool call and logs an internal cause host-side.
func (s *Server) recordTool(ctx context.Context, tool string, credential supportaccess.VerifiedCredential, response supportapi.Response) {
	if ctx == nil {
		ctx = context.Background()
	}

	result := resultOK
	if response.IsError() {
		result = resultToolError
	}

	s.record(ctx, accessRecord{result: result, tool: tool, principal: credential.Identity(), code: string(response.Code),
		status: response.Status})

	if cause := response.Cause(); cause != nil {
		s.logger().LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn, "MCP tool call failed", slog.String("tool", tool),
			slog.String("code", string(response.Code)), slog.String("cause", cause.Error()))
	}
}
