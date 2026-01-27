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

package config

import "golang.org/x/text/language"

var (
	// DefaultLanguageTags contains the list of supported languages.
	// Initialized with a sensible default list.
	DefaultLanguageTags = []language.Tag{
		language.English,
		language.German,
		language.French,
		language.Spanish,
		language.Italian,
		language.Portuguese,
		language.Russian,
		language.Chinese,
		language.Hindi,
		language.Persian,
		language.Arabic,
		language.Japanese,
	}
)
