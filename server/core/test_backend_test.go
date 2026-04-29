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

package core

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/util"
)

func TestTestBackendPassDBReturnsAccountAttribute(t *testing.T) {
	setupMinimalTestConfig(t)
	util.SetDefaultConfigFile(config.GetFile())
	util.SetDefaultEnvironment(config.GetEnvironment())

	manager := NewTestBackendManager("cbor-smoke", AuthDeps{})
	auth := &AuthState{}
	auth.Request.Username = "cbor@example.test"
	auth.Request.Password = secret.New("secret")
	auth.Request.Protocol = config.NewProtocol("imap")

	result, err := manager.PassDB(auth)
	if err != nil {
		t.Fatal(err)
	}

	values, ok := result.Attributes[result.AccountField]
	if !ok {
		t.Fatalf("expected account field %q in attributes", result.AccountField)
	}

	if len(values) != 1 || values[0] != auth.Request.Username {
		t.Fatalf("expected account attribute %q, got %#v", auth.Request.Username, values)
	}
}
