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

package core

// RESTResult is a handleAuthentication JSON result object for the Nauthilus REST API.
type RESTResult struct {
	// GUID represents a unique identifier for a session. It is a string field used in the RESTResult struct
	// and is also annotated with the json tag "session".
	GUID string `json:"session"`

	// Object represents a string field used in the RESTResult struct. It is annotated with the json tag "object".
	Object string `json:"object"`

	// Operation represents a string field used in the RESTResult struct. It is annotated with the json tag "operation".
	Operation string `json:"operation"`

	// Result represents the result field in the RESTResult struct. It can hold any type of value.
	// The field is annotated with the json tag "result".
	Result any `json:"result"`
}
