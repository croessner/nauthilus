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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetIdP(t *testing.T) {
	t.Run("NilFileSettings", func(t *testing.T) {
		var f *FileSettings
		idp := f.GetIdP()
		assert.NotNil(t, idp)
		assert.False(t, idp.OIDC.Enabled)
	})

	t.Run("NilIdPSection", func(t *testing.T) {
		f := &FileSettings{IdP: nil}
		idp := f.GetIdP()
		assert.NotNil(t, idp)
		assert.False(t, idp.OIDC.Enabled)
	})

	t.Run("ValidIdPSection", func(t *testing.T) {
		f := &FileSettings{
			IdP: &IdPSection{
				OIDC: OIDCConfig{
					Enabled: true,
					Issuer:  "https://test.example.com",
				},
			},
		}
		idp := f.GetIdP()
		assert.NotNil(t, idp)
		assert.True(t, idp.OIDC.Enabled)
		assert.Equal(t, "https://test.example.com", idp.OIDC.Issuer)
	})
}
