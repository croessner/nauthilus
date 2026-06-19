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
	LastUsed time.Time `json:"lastUsed"`
}

type persistentCredentialJSON struct {
	webauthn.Credential
	Name      string    `json:"name,omitempty"`
	LastUsed  time.Time `json:"lastUsed"`
	SignCount *uint32   `json:"signCount,omitempty"`
}

type persistentCredentialMetadataJSON struct {
	Name      string    `json:"name,omitempty"`
	LastUsed  time.Time `json:"lastUsed"`
	SignCount *uint32   `json:"signCount,omitempty"`
}

// MarshalJSON ensures the legacy top-level signCount field is present for compatibility.
func (p *PersistentCredential) MarshalJSON() ([]byte, error) {
	if p == nil {
		return nil, ErrNilPersistentCredential
	}

	signCount := p.Authenticator.SignCount
	aux := persistentCredentialJSON{
		Credential: p.Credential,
		Name:       p.Name,
		LastUsed:   p.LastUsed,
		SignCount:  &signCount,
	}

	return json.Marshal(aux)
}

// UnmarshalJSON preserves Nauthilus metadata while letting webauthn.Credential run its own migrations.
func (p *PersistentCredential) UnmarshalJSON(data []byte) error {
	if p == nil {
		return ErrNilPersistentCredential
	}

	var credential webauthn.Credential
	if err := json.Unmarshal(data, &credential); err != nil {
		return err
	}

	var metadata persistentCredentialMetadataJSON
	if err := json.Unmarshal(data, &metadata); err != nil {
		return err
	}

	p.Credential = credential
	p.Name = metadata.Name

	p.LastUsed = metadata.LastUsed
	if metadata.SignCount != nil {
		p.Authenticator.SignCount = *metadata.SignCount
	}

	p.RawJSON = string(data)

	return nil
}
