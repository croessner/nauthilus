// Copyright (C) 2026 Christian Roessner
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

package pluginapi

// StatusMessage is a protocol-neutral status signal returned by plugins.
type StatusMessage struct {
	Code        string
	MessageKey  string
	DefaultText string
	Temporary   bool
}

// LogField is one structured log key-value pair.
type LogField struct {
	Key   string
	Value any
}

// PolicyFact carries a typed policy value emitted by a plugin.
type PolicyFact struct {
	Attribute string
	Value     any
}

// AttributePatch describes subject attribute mutations returned by a plugin.
type AttributePatch struct {
	Set    map[string][]string
	Delete []string
}

// BackendServerRef identifies a backend server selected by an extension.
type BackendServerRef struct {
	Name      string
	Protocol  string
	Authority string
	Address   string
	Port      string
}

// BackendResult describes a password verification result from a backend plugin.
type BackendResult struct {
	Status        *StatusMessage
	Attributes    map[string][]string
	Facts         []PolicyFact
	Account       string
	BackendServer *BackendServerRef
	Authenticated bool
	UserFound     bool
}
