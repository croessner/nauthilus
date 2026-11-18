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

package lokisource

import (
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

// profileEntry binds one symptom to one exact log message literal of the Nauthilus code base.
type profileEntry struct {
	component string
	symptom   string
	literal   string
}

// diagnosticsProfile is the compiled nauthilus_diagnostics query profile. Every literal is the msg value of a log
// call in the code base; TestProfileLiteralsMatchSourceLogMessages keeps them bound to the source.
var diagnosticsProfile = []profileEntry{
	{supportops.ComponentLDAP, supportops.SymptomLDAPConnectionError, "LDAP connection error"},
	{supportops.ComponentLDAP, supportops.SymptomLDAPConnectionFailed, "LDAP connection failed"},
	{supportops.ComponentLDAP, supportops.SymptomLDAPSearchError, "LDAP search error"},
	{supportops.ComponentAuthBackend, supportops.SymptomAuthBackendsFailed, "All backends failed"},
	{supportops.ComponentAuthBackend, supportops.SymptomUnclassifiedBackendFailure, "Unclassified backend error answered as a temporary failure"},
	{supportops.ComponentRedis, supportops.SymptomRedisPipelineError, "Redis batching pipeline returned error"},
	{supportops.ComponentRedis, supportops.SymptomRedisWritePipelineFailed, "Execute write pipeline failed"},
	{supportops.ComponentClickHouseExport, supportops.SymptomClickHouseFlushFailed, "clickhouse pending batch flush failed"},
}

// profileQueries converts the compiled profile into engine entries; count builds the query of one literal.
func profileQueries(count func(literal string) func(int64) string) []windowsource.Entry {
	entries := make([]windowsource.Entry, 0, len(diagnosticsProfile))

	for _, entry := range diagnosticsProfile {
		entries = append(entries, windowsource.Entry{Component: entry.component, Symptom: entry.symptom, Query: count(entry.literal)})
	}

	return entries
}
