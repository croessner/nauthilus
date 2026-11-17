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

package clickhousestore

import (
	"strconv"
	"strings"
	"time"
)

// binder owns the typed parameters of one SQL request.
type binder struct {
	values  map[string]string
	counter int
}

// statement is one WHERE list of a parameterized SELECT. Values never enter the SQL text; only fixed fragments and
// validated identifiers do. Sibling statements share one binder, for example the two halves of a UNION.
type statement struct {
	bind       *binder
	conditions []string
}

// newStatement starts a statement bound to the deployment.
func newStatement(deployment string) *statement {
	stmt := &statement{bind: &binder{values: map[string]string{}}}
	stmt.where("deployment = " + stmt.text(deployment))

	return stmt
}

// sibling starts another WHERE list that shares the parameters, bound to the deployment.
func (s *statement) sibling(deployment string) *statement {
	stmt := &statement{bind: s.bind}
	stmt.where("deployment = " + stmt.text(deployment))

	return stmt
}

// params returns the bound parameters.
func (s *statement) params() map[string]string {
	return s.bind.values
}

// name returns a fresh parameter name.
func (s *statement) name() string {
	s.bind.counter++

	return "p" + strconv.Itoa(s.bind.counter)
}

// text binds a String value and returns its placeholder.
func (s *statement) text(value string) string {
	name := s.name()
	s.bind.values[name] = stringParam(value)

	return "{" + name + ":String}"
}

// texts binds an Array(String) value and returns its placeholder.
func (s *statement) texts(values []string) string {
	name := s.name()
	s.bind.values[name] = formatStrings(values)

	return "{" + name + ":Array(String)}"
}

// instant binds a DateTime64(3, 'UTC') value and returns its placeholder.
func (s *statement) instant(at time.Time) string {
	name := s.name()
	s.bind.values[name] = formatTime(at)

	return "{" + name + ":DateTime64(3, 'UTC')}"
}

// instants binds an Array(DateTime64(3, 'UTC')) value and returns its placeholder.
func (s *statement) instants(values []time.Time) string {
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		formatted = append(formatted, formatTime(value))
	}

	name := s.name()
	s.bind.values[name] = formatStrings(formatted)

	return "{" + name + ":Array(DateTime64(3, 'UTC'))}"
}

// integer binds an Int64 value and returns its placeholder.
func (s *statement) integer(value int64) string {
	name := s.name()
	s.bind.values[name] = strconv.FormatInt(value, 10)

	return "{" + name + ":Int64}"
}

// integers binds an Array(Int64) value and returns its placeholder.
func (s *statement) integers(values []int64) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.FormatInt(value, 10))
	}

	name := s.name()
	s.bind.values[name] = "[" + strings.Join(parts, ",") + "]"

	return "{" + name + ":Array(Int64)}"
}

// where appends a condition.
func (s *statement) where(condition string) {
	s.conditions = append(s.conditions, condition)
}

// timeRange appends a half-open time range on the given column.
func (s *statement) timeRange(column string, from, until time.Time) {
	s.where(column + " >= " + s.instant(from))
	s.where(column + " < " + s.instant(until))
}

// equalsIfSet appends an equality condition for a non-empty value.
func (s *statement) equalsIfSet(column, value string) {
	if value != "" {
		s.where(column + " = " + s.text(value))
	}
}

// whereClause renders the AND-joined conditions.
func (s *statement) whereClause() string {
	return " WHERE " + strings.Join(s.conditions, " AND ")
}

// anyOf renders an OR of non-empty alternatives, or a false literal when none remains.
func anyOf(alternatives ...string) string {
	var kept []string

	for _, alternative := range alternatives {
		if alternative != "" {
			kept = append(kept, alternative)
		}
	}

	if len(kept) == 0 {
		return "0"
	}

	return "(" + strings.Join(kept, " OR ") + ")"
}
