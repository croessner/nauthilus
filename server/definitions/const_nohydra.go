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

package definitions

// DbgHydra is a placeholder for the Hydra debug module when Hydra is disabled.
const DbgHydra DbgModule = 3

// DbgHydraName is a placeholder for the Hydra debug module name when Hydra is disabled.
const DbgHydraName = "hydra"

// ProtoOryHydra corresponds to the "ory-hydra" protocol (placeholder).
const ProtoOryHydra = "ory-hydra"

// ServOryHydra is the service identifier for Ory Hydra related flows (placeholder).
const ServOryHydra = "ory_hydra"
