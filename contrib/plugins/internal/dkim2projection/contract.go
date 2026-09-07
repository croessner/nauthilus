package dkim2projection

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"strings"
)

// HopInputFields declares every consumed verifier record field for pre-activation visibility and kind checks.
func HopInputFields() []pluginapi.DecisionFactInputFieldDescriptor {
	groups := []struct {
		kind  pluginapi.DecisionValueKind
		names string
	}{
		{pluginapi.DecisionValueKindInteger, "sequence message_instance change_count affected_header_count"},
		{pluginapi.DecisionValueKindBytes, "hop_binding recipe_digest"},
		{pluginapi.DecisionValueKindString, "signer_domain signature_state custody_transition recipe_mode recipe_body_mode history_header_state history_body_state body_availability"},
		{pluginapi.DecisionValueKindStrings, "signature_algorithms change_classes affected_headers"},
		{pluginapi.DecisionValueKindBoolean, "do_not_modify do_not_explode feedback feed_here exploded recipe_has_header_changes"},
	}
	result := make([]pluginapi.DecisionFactInputFieldDescriptor, 0, 23)

	for _, group := range groups {
		for _, name := range strings.Fields(group.names) {
			result = append(result, pluginapi.DecisionFactInputFieldDescriptor{Name: name, Kind: group.kind})
		}
	}

	return result
}
