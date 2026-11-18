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
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Request results of the transport audit and the request metric.
const (
	resultOK           = "ok"
	resultToolError    = "tool_error"
	resultUnauthorized = "unauthorized"
	resultForbidden    = "forbidden"
	resultRejected     = "rejected"
	resultRateLimited  = "rate_limited"
	resultBusy         = "busy"
	resultError        = "error"
)

// requestsTotal counts endpoint outcomes by a fixed, low-cardinality result label.
var requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{Name: "mcp_requests_total",
	Help: "MCP endpoint requests and tool calls by result."}, []string{"result"})

// accessRecord is one transport audit record. It never carries tokens, arguments, or results.
type accessRecord struct {
	result    string
	reason    string
	tool      string
	principal string
	code      string
	status    int
}

// record counts the outcome and writes the audit record when audit is enabled.
func (s *Server) record(ctx context.Context, entry accessRecord) {
	requestsTotal.WithLabelValues(entry.result).Inc()

	if !s.audit {
		return
	}

	attributes := []slog.Attr{slog.String("audit", "support_mcp"), slog.String("result", entry.result),
		slog.Int("status", entry.status)}

	if client := clientIPOf(ctx); client.IsValid() {
		attributes = append(attributes, slog.String("client_ip", client.String()))
	}

	for _, field := range [][2]string{{"reason", entry.reason}, {"tool", entry.tool}, {"principal", entry.principal},
		{"code", entry.code}} {
		if field[1] != "" {
			attributes = append(attributes, slog.String(field[0], field[1]))
		}
	}

	s.logger().LogAttrs(context.WithoutCancel(ctx), slog.LevelInfo, "support mcp access", attributes...)
}
