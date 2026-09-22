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
	stderrors "errors"
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/errors"
)

// luaNoProtocolConfig answers the way FileSettings does for a protocol this
// backend does not serve: no protocol and no error. It borrows mockConfig for
// the server section the metrics helpers read.
type luaNoProtocolConfig struct {
	mockConfig
}

func (c *luaNoProtocolConfig) GetLuaSearchProtocol(string, string) (*config.LuaSearchProtocol, error) {
	return nil, nil
}

// TestLuaPassDBDeclinesAProtocolItDoesNotServe pins that a Lua backend which
// does not serve a protocol says so with an error.
//
// Returning a nil result and a nil error instead reads one layer up as "this
// backend produced nothing", which ends the whole chain and fails the request -
// so a protocol served by only one backend of several would fail for every
// request the others were meant to answer. Worse, it would do so only for
// users nobody could find, while a known user with a wrong password still got
// a rejection from the backend that did serve the protocol. That difference is
// measurable from outside and enumerates accounts.
func TestLuaPassDBDeclinesAProtocolItDoesNotServe(t *testing.T) {
	lm := &luaManagerImpl{
		backendName: "default",
		deps:        AuthDeps{Cfg: &luaNoProtocolConfig{}},
	}

	req, _ := http.NewRequest("GET", "/", nil)
	auth := &AuthState{deps: lm.deps}
	auth.Request.HTTPClientRequest = req
	auth.Request.Username = "jdoe"
	auth.Request.Protocol = new(config.Protocol)
	auth.Request.Protocol.Set("smtp")

	result, err := lm.PassDB(auth)

	if result != nil {
		t.Fatalf("a backend that does not serve the protocol must not produce a result, got %+v", result)
	}

	if err == nil {
		t.Fatal("a nil result with a nil error ends the backend chain and fails the request")
	}

	if !errors.IsBackendNotResponsible(err) {
		t.Fatalf("declining a protocol must be reported as a declining backend, got %v", err)
	}

	if errors.IsBackendTechnicalFailure(err) {
		t.Fatalf("declining a protocol is a configuration choice, not a failure, got %v", err)
	}

	// The pipeline reserves this error for "the backend returned nothing at
	// all", which aborts the chain. A decline must not look like that.
	if stderrors.Is(err, errors.ErrNoPassDBResult) {
		t.Fatal("a decline must not be reported as a missing result")
	}
}
