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

package decision

import "strings"

const maximumFactIDLength = 192

// FactSource identifies the authority class that produced one fact.
type FactSource string

const (
	// FactSourceCaller identifies admitted caller assertions.
	FactSourceCaller FactSource = "caller"

	// FactSourceToken identifies validated token claims.
	FactSourceToken FactSource = "token"

	// FactSourceTransport identifies server-observed transport facts.
	FactSourceTransport FactSource = "transport"

	// FactSourceNauthilus identifies host-computed facts.
	FactSourceNauthilus FactSource = "nauthilus"

	// FactSourceBackend identifies backend-owned facts.
	FactSourceBackend FactSource = "backend"

	// FactSourceLua identifies facts from one named Lua provider.
	FactSourceLua FactSource = "lua"

	// FactSourcePlugin identifies facts from one qualified native provider.
	FactSourcePlugin FactSource = "plugin"
)

// FactCategory identifies the policy category of a fact.
type FactCategory string

const (
	// FactCategorySubject identifies evaluated-subject facts.
	FactCategorySubject FactCategory = "subject"

	// FactCategoryResource identifies evaluated-resource facts.
	FactCategoryResource FactCategory = "resource"

	// FactCategoryEnvironment identifies environment and additional input facts.
	FactCategoryEnvironment FactCategory = "environment"
)

// Provenance records immutable fact source ownership.
type Provenance struct {
	authority string
	component string
	source    FactSource
}

// NewProvenance validates and constructs source ownership metadata.
func NewProvenance(source FactSource, authority string, component string) (Provenance, error) {
	if !source.valid() {
		return Provenance{}, newContractError(
			ErrFactSource,
			ErrorCodeFactSource,
			"fact.provenance.source",
			"must be a registered source class",
		)
	}

	if !validIdentityText(authority) || !validIdentityText(component) {
		return Provenance{}, newContractError(
			ErrInvalidFact,
			ErrorCodeInvalidFact,
			"fact.provenance",
			"authority and component must be non-empty bounded UTF-8",
		)
	}

	return Provenance{source: source, authority: authority, component: component}, nil
}

// Source returns the immutable source class.
func (p Provenance) Source() FactSource {
	return p.source
}

// Authority returns the host-assigned authority identity.
func (p Provenance) Authority() string {
	return p.authority
}

// Component returns the host-assigned source component.
func (p Provenance) Component() string {
	return p.component
}

// valid reports whether provenance satisfies its constructor invariant.
func (p Provenance) valid() bool {
	return p.source.valid() && validIdentityText(p.authority) && validIdentityText(p.component)
}

// valid reports whether the source is a closed contract member.
func (s FactSource) valid() bool {
	switch s {
	case FactSourceCaller,
		FactSourceToken,
		FactSourceTransport,
		FactSourceNauthilus,
		FactSourceBackend,
		FactSourceLua,
		FactSourcePlugin:
		return true
	default:
		return false
	}
}

// Fact is one immutable strict value with canonical provenance.
type Fact struct {
	id         string
	value      Value
	provenance Provenance
	category   FactCategory
}

// NewFact validates canonical identity, source ownership, and strict value state.
func NewFact(id string, category FactCategory, value Value, provenance Provenance) (Fact, error) {
	if !validFactID(id) {
		return Fact{}, newContractError(
			ErrInvalidFact,
			ErrorCodeInvalidFact,
			"fact.id",
			"must be a bounded lowercase dotted identifier",
		)
	}

	if !category.valid() || !value.valid() || !provenance.valid() {
		return Fact{}, newContractError(
			ErrInvalidFact,
			ErrorCodeInvalidFact,
			"fact",
			"category, value, and provenance must be constructor-validated",
		)
	}

	if err := validateFactOwnership(id, provenance); err != nil {
		return Fact{}, err
	}

	return Fact{id: id, value: value, provenance: provenance, category: category}, nil
}

// ID returns the canonical fact identity.
func (f Fact) ID() string {
	return f.id
}

// Category returns the fact category.
func (f Fact) Category() FactCategory {
	return f.category
}

// Value returns the immutable strict value.
func (f Fact) Value() Value {
	return f.value
}

// Provenance returns the immutable source metadata.
func (f Fact) Provenance() Provenance {
	return f.provenance
}

// valid reports whether the fact satisfies its constructor invariant.
func (f Fact) valid() bool {
	return validFactID(f.id) && f.category.valid() && f.value.valid() && f.provenance.valid()
}

// valid reports whether the category is a closed contract member.
func (c FactCategory) valid() bool {
	switch c {
	case FactCategorySubject, FactCategoryResource, FactCategoryEnvironment:
		return true
	default:
		return false
	}
}

// FactSet is a collision-free immutable fact collection.
type FactSet struct {
	index map[string]int
	facts []Fact
}

// NewFactSet validates facts and rejects duplicate canonical ownership.
func NewFactSet(input []Fact) (FactSet, error) {
	result := FactSet{
		index: make(map[string]int, len(input)),
		facts: make([]Fact, 0, len(input)),
	}

	for _, fact := range input {
		if !fact.valid() {
			return FactSet{}, newContractError(
				ErrInvalidFact,
				ErrorCodeInvalidFact,
				"facts",
				"contains an unconstructed fact",
			)
		}

		if _, exists := result.index[fact.id]; exists {
			return FactSet{}, newContractError(
				ErrFactCollision,
				ErrorCodeFactCollision,
				fact.id,
				"canonical fact already has an owner",
			)
		}

		result.index[fact.id] = len(result.facts)
		result.facts = append(result.facts, fact)
	}

	return result, nil
}

// Len returns the number of facts.
func (s FactSet) Len() int {
	return len(s.facts)
}

// Get returns one immutable fact by canonical ID.
func (s FactSet) Get(id string) (Fact, bool) {
	index, ok := s.index[id]
	if !ok {
		return Fact{}, false
	}

	return s.facts[index], true
}

// Facts returns a detached ordered fact slice.
func (s FactSet) Facts() []Fact {
	return append([]Fact(nil), s.facts...)
}

// validFactID validates the generic canonical fact grammar.
func validFactID(id string) bool {
	if len(id) == 0 || len(id) > maximumFactIDLength {
		return false
	}

	segments := strings.Split(id, ".")
	if len(segments) < 2 {
		return false
	}

	for _, segment := range segments {
		if !validIdentifierSegment(segment, true) {
			return false
		}
	}

	return true
}

// validateFactOwnership binds every canonical family and provider owner to provenance.
func validateFactOwnership(id string, provenance Provenance) error {
	prefix := strings.SplitN(id, ".", 2)[0]
	if provenance.source == FactSourceCaller {
		return validateCallerFactPrefix(prefix)
	}

	if prefix != string(provenance.source) {
		return newContractError(
			ErrFactSource,
			ErrorCodeFactSource,
			id,
			"canonical fact family does not match its source",
		)
	}

	if provenance.source == FactSourceLua || provenance.source == FactSourcePlugin {
		return validateProviderFactOwner(id, provenance.authority)
	}

	return nil
}

// validateProviderFactOwner binds lua/plugin fact identity to host-assigned authority.
func validateProviderFactOwner(id string, authority string) error {
	segments := strings.Split(id, ".")
	if len(segments) < 3 || !validIdentifierSegment(authority, true) || segments[1] != authority {
		return newContractError(
			ErrFactSource,
			ErrorCodeFactSource,
			id,
			"provider fact owner must match host-assigned provenance authority",
		)
	}

	return nil
}

// validateCallerFactPrefix restricts callers to assertion-owned fact families.
func validateCallerFactPrefix(prefix string) error {
	switch prefix {
	case "subject", "resource", "environment", "input":
		return nil
	case "caller", "token", "transport", "nauthilus", "backend", "lua", "plugin":
		return newContractError(
			ErrReservedFact,
			ErrorCodeReservedFact,
			prefix,
			"trusted fact family cannot be caller supplied",
		)
	default:
		return newContractError(
			ErrFactSource,
			ErrorCodeFactSource,
			prefix,
			"caller facts require subject, resource, environment, or input ownership",
		)
	}
}
