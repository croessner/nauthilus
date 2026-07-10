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

import "strconv"

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

// ResponseHeaderMutation describes allowed response header set and delete operations.
type ResponseHeaderMutation struct {
	Set    map[string][]string
	Delete []string
}

// ResponseMutation carries request-time response changes without exposing server internals.
type ResponseMutation struct {
	Headers      ResponseHeaderMutation
	StatusHeader bool
}

// BackendServerRef identifies a backend server selected by an extension.
type BackendServerRef struct {
	Name      string
	Protocol  string
	Authority string
	Address   string
	Port      string
}

// BackendServerCandidate describes one host-provided backend target safe for plugin selection logic.
type BackendServerCandidate struct {
	Name      string
	Protocol  string
	Authority string
	Address   string
	Port      int
	HAProxyV2 bool
	Alive     bool
}

// Ref converts the candidate into the value returned through SubjectResult.SelectedBackend.
func (c BackendServerCandidate) Ref() BackendServerRef {
	port := ""
	if c.Port > 0 {
		port = strconv.Itoa(c.Port)
	}

	return BackendServerRef{
		Name:      c.Name,
		Protocol:  c.Protocol,
		Authority: c.Authority,
		Address:   c.Address,
		Port:      port,
	}
}

// BackendResultPatch describes explicit value-only backend result changes from subject sources.
type BackendResultPatch struct {
	SelectedBackend *BackendServerRef
	Attributes      AttributePatch
	Authenticated   *bool
	UserFound       *bool
	Account         string
	AccountField    string
}

// BackendIdentityResult carries identity metadata returned by a backend plugin.
type BackendIdentityResult struct {
	UniqueUserIDField       string
	DisplayNameField        string
	TOTPSecretField         string
	TOTPRecoveryField       string
	Groups                  []string
	GroupDistinguishedNames []string
}

// BackendResult describes a password verification result from a backend plugin.
type BackendResult struct {
	Status        *StatusMessage
	Attributes    map[string][]string
	Facts         []PolicyFact
	Identity      BackendIdentityResult
	Account       string
	AccountField  string
	BackendServer *BackendServerRef
	Authenticated bool
	UserFound     bool
}
