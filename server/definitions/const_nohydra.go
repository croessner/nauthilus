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

//go:build !hydra
// +build !hydra

package definitions

// ProtoOryHydra corresponds to the "ory-hydra" protocol.
// It remains defined in non-hydra builds to keep references compiling.
const ProtoOryHydra = "ory-hydra"

// ServOryHydra is the service identifier for Ory Hydra related flows.
// It remains defined in non-hydra builds for API parity.
const ServOryHydra = "ory_hydra"

// DbgHydra is the debugging module selector for Hydra related debug output.
// In non-hydra builds, it maps to DbgNone to effectively disable hydra-specific logging.
const DbgHydra DbgModule = DbgNone

// DbgHydraName is the human-readable name for the Hydra debug module.
// Keeping the name available allows configuration to include "hydra" without build errors.
const DbgHydraName = "hydra"
