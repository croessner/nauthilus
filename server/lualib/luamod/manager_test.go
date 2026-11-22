// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package luamod

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/lualib"
)

func TestRequestI18NRuntimeDoesNotFallBackToProcessDefault(t *testing.T) {
	processDefault := lualib.DefaultI18NRuntime()
	runtime := requestI18NRuntime(context.Background())

	if runtime == nil {
		t.Fatal("requestI18NRuntime() = nil, would select the process default")
	}

	if runtime == processDefault {
		t.Fatal("requestI18NRuntime() returned the process default")
	}
}
