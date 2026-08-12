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

const maximumOpaqueCredentialBytes = 64 * 1024

const (
	// CheckpointFinalDecision is the sole checkpoint driven by generic unary evaluation.
	CheckpointFinalDecision = "final_decision"
)

// AuthenticationEvidence is bounded host-created credential and transport presentation.
type AuthenticationEvidence struct {
	Kind          string
	Credential    []byte
	TransportKind string
	Peer          string
	MTLSIdentity  string
	Protected     bool
}

// AuthenticationInput is deeply owned opaque evidence for the generation authenticator.
type AuthenticationInput struct {
	credential    []byte
	kind          string
	transportKind string
	peer          string
	mtlsIdentity  string
	protected     bool
}

// NewAuthenticationInput validates and owns host-created authentication evidence.
func NewAuthenticationInput(input AuthenticationEvidence) (AuthenticationInput, error) {
	if !validIdentityText(input.Kind) || !validIdentityText(input.TransportKind) {
		return AuthenticationInput{}, invalidCaller(
			"authentication",
			"kind and transport kind must be non-empty bounded UTF-8",
		)
	}

	if len(input.Credential) == 0 || len(input.Credential) > maximumOpaqueCredentialBytes {
		return AuthenticationInput{}, invalidCaller(
			"authentication.credential",
			"must contain bounded opaque credential evidence",
		)
	}

	if (input.Peer != "" && !validIdentityText(input.Peer)) ||
		(input.MTLSIdentity != "" && !validIdentityText(input.MTLSIdentity)) {
		return AuthenticationInput{}, invalidCaller(
			"authentication.transport",
			"contains invalid peer or mutual-TLS identity text",
		)
	}

	return AuthenticationInput{
		credential:    append([]byte(nil), input.Credential...),
		kind:          input.Kind,
		transportKind: input.TransportKind,
		peer:          input.Peer,
		mtlsIdentity:  input.MTLSIdentity,
		protected:     input.Protected,
	}, nil
}

// Kind returns the host-selected credential presentation kind.
func (i AuthenticationInput) Kind() string {
	return i.kind
}

// Credential returns a detached copy of opaque credential material.
func (i AuthenticationInput) Credential() []byte {
	return append([]byte(nil), i.credential...)
}

// TransportKind returns the host-selected transport kind.
func (i AuthenticationInput) TransportKind() string {
	return i.transportKind
}

// Peer returns bounded host-observed peer evidence.
func (i AuthenticationInput) Peer() string {
	return i.peer
}

// MTLSIdentity returns the verified mutual-TLS presentation identity.
func (i AuthenticationInput) MTLSIdentity() string {
	return i.mtlsIdentity
}

// Protected reports host-established protected transport evidence.
func (i AuthenticationInput) Protected() bool {
	return i.protected
}

// Invocation combines one unary request with opaque host-created authentication evidence.
type Invocation struct {
	Request        DecisionRequestInput
	Authentication AuthenticationInput
}

// Checkpoint is one immutable checkpoint and its current admitted facts.
type Checkpoint struct {
	facts FactSet
	name  string
}

// NewCheckpoint validates and owns one checkpoint evaluation input.
func NewCheckpoint(name string, facts FactSet) (Checkpoint, error) {
	if !validAction(name) {
		return Checkpoint{}, invalidRequest(
			"checkpoint",
			"must be a canonical bounded checkpoint identity",
		)
	}

	ownedFacts, err := NewFactSet(facts.Facts())
	if err != nil {
		return Checkpoint{}, err
	}

	return Checkpoint{name: name, facts: ownedFacts}, nil
}

// Name returns the exact checkpoint identity.
func (c Checkpoint) Name() string {
	return c.name
}

// Facts returns a detached immutable fact set.
func (c Checkpoint) Facts() FactSet {
	facts, err := NewFactSet(c.facts.Facts())
	if err != nil {
		return FactSet{}
	}

	return facts
}
