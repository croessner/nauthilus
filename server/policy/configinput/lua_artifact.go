// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
)

// LuaArtifactReader exposes only immutable candidate-owned script bytes.
type LuaArtifactReader interface {
	ReadFile(string) ([]byte, error)
}

// readCapturedLuaArtifact returns one detached script only from the candidate artifact owner.
func readCapturedLuaArtifact(
	artifacts LuaArtifactReader,
	path string,
	maximumSize int,
) ([]byte, error) {
	if artifacts == nil {
		return nil, fmt.Errorf("policy Lua artifact snapshot is unavailable")
	}

	source, err := artifacts.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(source) == 0 || maximumSize > 0 && len(source) > maximumSize {
		clear(source)

		return nil, fmt.Errorf("policy Lua artifact size is invalid")
	}

	return source, nil
}
