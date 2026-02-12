// Copyright (C) 2025 Christian Rößner
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

package mfa

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrNilPersistentCredential is returned when a nil *PersistentCredential receiver is used.
var ErrNilPersistentCredential = errors.New("nil PersistentCredential receiver")

// PersistentCredential wraps webauthn.Credential to add persistent metadata.
type PersistentCredential struct {
	webauthn.Credential
	Name     string    `json:"name,omitempty"`
	RawJSON  string    `json:"-"`
	LastUsed time.Time `json:"lastUsed,omitempty"`
}

type persistentCredentialJSON struct {
	webauthn.Credential
	Name      string    `json:"name,omitempty"`
	LastUsed  time.Time `json:"lastUsed,omitempty"`
	SignCount *uint32   `json:"signCount,omitempty"`
}

// MarshalJSON ensures the legacy top-level signCount field is present for compatibility.
func (p *PersistentCredential) MarshalJSON() ([]byte, error) {
	if p == nil {
		return nil, ErrNilPersistentCredential
	}

	signCount := p.Credential.Authenticator.SignCount
	aux := persistentCredentialJSON{
		Credential: p.Credential,
		Name:       p.Name,
		LastUsed:   p.LastUsed,
		SignCount:  &signCount,
	}

	return json.Marshal(aux)
}

// UnmarshalJSON maps a legacy top-level signCount field into Authenticator.SignCount when present.
func (p *PersistentCredential) UnmarshalJSON(data []byte) error {
	if p == nil {
		return ErrNilPersistentCredential
	}

	var aux persistentCredentialJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.Credential = aux.Credential
	p.Name = aux.Name
	p.LastUsed = aux.LastUsed
	if aux.SignCount != nil {
		p.Credential.Authenticator.SignCount = *aux.SignCount
	}

	p.RawJSON = string(data)

	return nil
}
