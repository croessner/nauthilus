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

package dbmock

import (
	"fmt"
	"strings"
)

func describeCall(call Call) string {
	query := normalizeSQL(call.Query)
	mode := "direct"
	if call.Prepared {
		mode = "prepared"
	}

	if len(call.Args) == 0 {
		return fmt.Sprintf("%s[%s] query=%q args=[]", call.Kind, mode, query)
	}

	return fmt.Sprintf("%s[%s] query=%q args=%#v", call.Kind, mode, query, call.Args)
}

func describeExpectation(exp Expectation) string {
	switch typed := exp.(type) {
	case *ExecExpectation:
		return formatExpectation("exec", typed.prepared, typed.query, typed.args)
	case *QueryExpectation:
		return formatExpectation("query", typed.prepared, typed.query, typed.args)
	case *PrepareExpectation:
		return formatExpectation("prepare", false, typed.query, typed.args)
	case *TxExpectation:
		return fmt.Sprintf("tx query=%q args=[]", typed.kind)
	default:
		return fmt.Sprintf("kind=%q", exp.Kind())
	}
}

func formatExpectation(kind string, prepared bool, query string, args []any) string {
	mode := "direct"
	if prepared {
		mode = "prepared"
	}

	normalizedQuery := normalizeSQL(query)
	if normalizedQuery == "" {
		normalizedQuery = strings.TrimSpace(query)
	}

	return fmt.Sprintf("%s[%s] query=%q args=%#v", kind, mode, normalizedQuery, args)
}
