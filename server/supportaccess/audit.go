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

package supportaccess

import (
	"context"
	"log/slog"
	"regexp"
	"time"
)

// auditReferencePattern bounds the unverified audit annotation a caller may attach to a request.
var auditReferencePattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,64}$`)

// AuditEntry is one controlled audit record of a support operation. It holds no subject in clear text, no filter
// values, and no evidence; services that look up a person record only a domain-separated subject digest.
type AuditEntry struct {
	At             time.Time
	Service        string
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
	RecordSupportAudit(ctx context.Context, entry AuditEntry)
}

// LogAuditRecorder writes audit entries as structured log records ("support <service> access", audit=support_<service>).
type LogAuditRecorder struct {
	Logger *slog.Logger
}

// RecordSupportAudit logs one audit entry at info level.
func (r LogAuditRecorder) RecordSupportAudit(ctx context.Context, entry AuditEntry) {
	if r.Logger == nil {
		return
	}

	r.Logger.LogAttrs(ctx, slog.LevelInfo, "support "+entry.Service+" access",
		slog.String("audit", "support_"+entry.Service),
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

// ValidAuditReference reports whether an audit reference is empty or matches the bounded format.
func ValidAuditReference(reference string) bool {
	return reference == "" || auditReferencePattern.MatchString(reference)
}

// BoundedAuditReference keeps an unvalidated audit reference out of the log unless it matches the bounded format.
func BoundedAuditReference(reference string) string {
	if !ValidAuditReference(reference) {
		return ""
	}

	return reference
}
