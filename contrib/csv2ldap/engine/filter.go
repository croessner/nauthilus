// Copyright (C) 2024 Christian Rößner
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

package engine

import "strings"

// AllowOKProtocols filters for ExpectedOK==true and allowed protocols.
type AllowOKProtocols struct {
	allowed map[string]struct{}
}

// NewAllowOKProtocols constructs a filter for the provided protocols.
func NewAllowOKProtocols(protocols []string) *AllowOKProtocols {
	m := make(map[string]struct{}, len(protocols))
	for _, p := range protocols {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			m[p] = struct{}{}
		}
	}

	return &AllowOKProtocols{allowed: m}
}

// Allow accepts only records that are expected OK and protocol is in allowed set.
func (f *AllowOKProtocols) Allow(r *Record) bool {
	if r == nil || !r.ExpectedOK {
		return false
	}

	_, ok := f.allowed[strings.ToLower(strings.TrimSpace(r.Protocol))]

	return ok
}
