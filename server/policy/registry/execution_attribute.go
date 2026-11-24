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

package registry

import (
	"slices"

	"github.com/croessner/nauthilus/v4/server/policy"
)

const (
	// DetailStatusMessage names the public response-message detail of a generated execution fact.
	DetailStatusMessage = "status_message"

	// statusMessageMaxLength bounds the public status message a source may contribute.
	statusMessageMaxLength = 256
)

// ExecutionAttributeInput describes one host-owned boolean result fact of a scheduled authn source.
type ExecutionAttributeInput struct {
	Operations    []policy.Operation
	ID            string
	ProducerType  string
	ProducerCheck string
	Stage         policy.Stage
	Category      AttributeCategory
	ProducerOrder uint32
	StatusMessage bool
}

// NewExecutionAttribute builds the definition the standard-auth rules and configured rules consume for one
// generated source result. Lua and native sources share it, so both expose the same fact vocabulary.
func NewExecutionAttribute(input ExecutionAttributeInput) AttributeDefinition {
	definition := AttributeDefinition{
		ID:            input.ID,
		Stage:         input.Stage,
		Operations:    slices.Clone(input.Operations),
		ProducerTypes: []string{input.ProducerType},
		ProducerCheck: input.ProducerCheck,
		ProducerOrder: input.ProducerOrder,
		Category:      input.Category,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
	}

	if input.StatusMessage {
		definition.Details = StatusMessageDetails()
	}

	return definition
}

// StatusMessageDetails returns detached public response-message metadata for one execution fact.
func StatusMessageDetails() map[string]DetailDefinition {
	return map[string]DetailDefinition{
		DetailStatusMessage: {
			Type: AttributeTypeString, Sensitivity: DetailSensitivityPublic,
			Purpose: DetailPurposeResponseMessage, MaxLength: statusMessageMaxLength,
		},
	}
}
