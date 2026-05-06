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

package core

// RelayDomainPolicyFact is the request-local policy view of relay-domain evaluation.
type RelayDomainPolicyFact struct {
	Value           string
	MatchedDomain   string
	ConfiguredCount int
	Present         bool
	Known           bool
	Rejected        bool
	StaticMatch     bool
	SoftAllowlisted bool
}

// RBLPolicyFact is the request-local policy view of aggregate RBL evaluation.
type RBLPolicyFact struct {
	Lists                  []RBLListPolicyFact
	MatchedLists           []string
	Score                  int
	Threshold              int
	MatchedCount           int
	ListCount              int
	AllowFailureErrorCount int
	EffectiveError         bool
	SoftAllowlisted        bool
	IPAllowlisted          bool
}

// RBLListPolicyFact is the request-local policy view of one configured RBL list.
type RBLListPolicyFact struct {
	Name         string
	Host         string
	Query        string
	ReturnCode   string
	ReasonCode   string
	IPFamily     string
	Weight       int
	Listed       bool
	Error        bool
	AllowFailure bool
}
