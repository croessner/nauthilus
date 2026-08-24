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

package admission

import (
	"math"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

const logicalLengthBytes = 8

type logicalSizer struct {
	total int
}

// logicalRequestSize measures transport-independent logical fields with deterministic framing.
func logicalRequestSize(request decision.DecisionRequest) int {
	sizer := &logicalSizer{}
	sizer.addString(request.Version())
	sizer.addString(request.RequestID().String())
	sizer.addString(request.Target().Namespace())
	sizer.addString(request.Target().Action())
	sizer.addEntity(request.Subject())
	sizer.addEntity(request.Resource())
	sizer.addEnvironment(request.Environment())
	sizer.addValueMap(request.Attributes())
	sizer.add(1)

	return sizer.total
}

// addEntity measures one entity's identity and sorted attribute map.
func (s *logicalSizer) addEntity(entity decision.Entity) {
	s.addString(entity.Type())
	s.addString(entity.ID())
	s.addValueMap(entity.Attributes())
}

// addEnvironment measures the fixed environment fields and sorted attribute map.
func (s *logicalSizer) addEnvironment(environment decision.Environment) {
	s.addString(environment.Service())
	s.addString(environment.Instance())
	s.addString(environment.Protocol())
	s.addValueMap(environment.Attributes())
}

// addValueMap measures canonical keys and strict value payloads in sorted order.
func (s *logicalSizer) addValueMap(values decision.ValueMap) {
	s.add(logicalLengthBytes)

	owned := values.Values()

	for _, key := range sortedValueKeys(values) {
		s.addString(key)
		s.addValue(owned[key])
	}
}

// addValue measures one strict value with a type tag and deterministic member framing.
func (s *logicalSizer) addValue(value decision.Value) {
	s.add(1)

	switch value.Kind() {
	case decision.ValueKindString:
		member, _ := value.StringValue()
		s.addString(member)
	case decision.ValueKindBoolean:
		s.add(1)
	case decision.ValueKindInteger, decision.ValueKindDouble, decision.ValueKindTimestamp:
		s.add(8)
	case decision.ValueKindStrings:
		members, _ := value.Strings()

		s.add(logicalLengthBytes)

		for _, member := range members {
			s.addString(member)
		}
	case decision.ValueKindBytes:
		member, _ := value.Bytes()

		s.add(logicalLengthBytes)
		s.add(len(member))
	default:
		s.total = math.MaxInt
	}
}

// addString measures UTF-8 bytes plus an unambiguous logical length prefix.
func (s *logicalSizer) addString(value string) {
	s.add(logicalLengthBytes)
	s.add(len(value))
}

// add saturates on overflow so an attacker-controlled size can never wrap below a limit.
func (s *logicalSizer) add(value int) {
	if value < 0 || s.total > math.MaxInt-value {
		s.total = math.MaxInt

		return
	}

	s.total += value
}
