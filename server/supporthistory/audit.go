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

package supporthistory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"
)

const auditDigestDomain = "nauthilus.support_history.audit.v1\x00"

// AuditEntry is one controlled audit record of a history operation. It holds no subject in clear text, no filter
// values, and no evidence; the subject digest lets an operator check whether a known name was looked up.
type AuditEntry struct {
	At             time.Time
	Operation      string
	CallerIdentity string
	CallerMethod   string
	Projection     string
	SubjectDigest  string
	AuditReference string
	ResultCode     string
	Duration       time.Duration
	Results        int
	Allowed        bool
}

// AuditRecorder receives audit entries; it must not block.
type AuditRecorder interface {
	RecordHistoryAudit(ctx context.Context, entry AuditEntry)
}

// subjectDigest returns a domain-separated digest of a normalized subject, or an empty string.
func subjectDigest(values ...string) string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		normalized = append(normalized, strings.TrimSpace(value))
	}

	joined := strings.Join(normalized, "\x00")
	if strings.Trim(joined, "\x00") == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(auditDigestDomain + strings.ToLower(joined)))

	return hex.EncodeToString(sum[:16])
}

// LogAuditRecorder writes audit entries as structured log records.
type LogAuditRecorder struct {
	Logger *slog.Logger
}

// RecordHistoryAudit logs one audit entry at info level.
func (r LogAuditRecorder) RecordHistoryAudit(ctx context.Context, entry AuditEntry) {
	if r.Logger == nil {
		return
	}

	r.Logger.LogAttrs(ctx, slog.LevelInfo, "support history access",
		slog.String("audit", "support_history"),
		slog.String("operation", entry.Operation),
		slog.String("caller", entry.CallerIdentity),
		slog.String("caller_method", entry.CallerMethod),
		slog.String("projection", entry.Projection),
		slog.Bool("allowed", entry.Allowed),
		slog.String("result_code", entry.ResultCode),
		slog.Int("results", entry.Results),
		slog.String("subject_digest", entry.SubjectDigest),
		slog.String("audit_reference", entry.AuditReference),
		slog.Duration("duration", entry.Duration),
	)
}
