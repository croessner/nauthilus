// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import "fmt"

// validateProviderInputSchemas checks each activated input contract against the exact completed target schema.
func (s *BindingSet) validateProviderInputSchemas(target CompiledTarget) error {
	for _, id := range target.ProviderIDs() {
		binding, exists := s.factProviders[id]
		if !exists {
			continue
		}

		validator, requiresSchema := binding.Provider.(FactProviderSchemaValidator)
		if !requiresSchema {
			continue
		}

		if err := validator.ValidateInputTarget(target); err != nil {
			return fmt.Errorf("%w: target %s provider %s input contract: %v", ErrInvalidGenerationBinding, target.Target().String(), id, err)
		}
	}

	return nil
}
