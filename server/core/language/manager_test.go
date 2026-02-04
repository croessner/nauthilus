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

package language

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name      string
		languages []string
		wantErr   bool
	}{
		{
			name:      "Default languages",
			languages: nil,
			wantErr:   false,
		},
		{
			name:      "Configured languages",
			languages: []string{"en", "de"},
			wantErr:   false,
		},
		{
			name:      "Non-existent language",
			languages: []string{"xx"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.FileSettings{}
			cfg.Server = &config.ServerSection{}
			cfg.Server.Frontend.LanguageResources = "../../resources"
			cfg.Server.Frontend.Languages = tt.languages

			m, err := NewManager(cfg, nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, m)
				if tt.languages != nil {
					assert.Equal(t, len(tt.languages), len(m.GetTags()))
				} else {
					assert.Equal(t, len(config.DefaultLanguageTags), len(m.GetTags()))
				}
			}
		})
	}
}
