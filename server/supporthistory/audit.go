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
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

const auditDigestDomain = "nauthilus.support_history.audit.v1\x00"

// auditService names the history service in shared audit records.
const auditService = "history"

// AuditEntry is one controlled audit record of a history operation (shared support audit type).
type AuditEntry = supportaccess.AuditEntry

// AuditRecorder receives audit entries; it must not block (shared support audit type).
type AuditRecorder = supportaccess.AuditRecorder

// LogAuditRecorder writes audit entries as structured log records (shared support audit type).
type LogAuditRecorder = supportaccess.LogAuditRecorder

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
