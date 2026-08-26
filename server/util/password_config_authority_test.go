// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package util

import (
	"os"
	"strings"
	"testing"
)

func TestPasswordPreparationHasNoAmbientConfigAuthority(t *testing.T) {
	source, err := os.ReadFile("util.go")
	if err != nil {
		t.Fatalf("read util source: %v", err)
	}

	for _, forbidden := range []string{
		"func PreparePassword(",
		"func PreparePasswordBytes(",
		"func SetDefaultConfigFile(",
		"func getDefaultConfigFile(",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Errorf("password preparation retains ambient config authority %q", forbidden)
		}
	}
}
