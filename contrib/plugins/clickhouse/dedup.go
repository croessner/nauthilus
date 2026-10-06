// Copyright (C) 2026 Christian Roessner
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

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// loginDedupKey identifies a login context and outcome without exposing its fields in Redis keys.
// JSON encodes string boundaries unambiguously; request IDs and source ports are deliberately excluded.
func loginDedupKey(snapshot pluginapi.RequestSnapshot) string {
	fields := []string{
		strings.TrimSpace(snapshot.Username), strings.TrimSpace(snapshot.ClientIP),
		snapshot.Protocol, snapshot.Service, snapshot.Method,
		snapshot.ClientID, snapshot.OIDCCID, snapshot.SAMLEntityID,
		snapshot.IDP.ClientID, snapshot.IDP.GrantType,
		snapshot.IDP.MFAMethod, strconv.FormatBool(snapshot.IDP.MFACompleted),
		strconv.FormatBool(snapshot.Runtime.Authenticated), strconv.FormatBool(snapshot.Runtime.Authorized),
		strconv.Itoa(snapshot.Diagnostics.HTTPStatus), snapshot.Diagnostics.StatusMessage,
	}
	// A slice of strings is always JSON-serializable.
	encoded, _ := json.Marshal(fields)
	digest := sha256.Sum256(encoded)

	return dedupKeyPrefix + "v2:" + hex.EncodeToString(digest[:])
}
