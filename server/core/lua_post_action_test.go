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

package core_test

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"go.opentelemetry.io/otel/trace"
)

func TestRunLuaPostAction_EnqueuesAndCopies(t *testing.T) {
	// Initialize action channel
	corepkg.SetDefaultConfigFile(config.GetFile())
	_ = action.NewWorker(config.GetFile(), log.GetLogger())

	done := make(chan struct{})
	go func() {
		act := <-action.RequestChan
		if act == nil {
			t.Errorf("action must not be nil")
			close(done)

			return
		}

		if act.LuaAction != definitions.LuaActionPost {
			t.Errorf("expected LuaActionPost, got %v", act.LuaAction)
		}

		if act.CommonRequest == nil {
			t.Errorf("CommonRequest must not be nil")
		} else {
			if act.CommonRequest.StatusMessage == nil || *act.CommonRequest.StatusMessage != "status-1" {
				t.Errorf("status message copy mismatch: %v", act.CommonRequest.StatusMessage)
			}

			if act.CommonRequest.ClientNet != "10.0.0.0/24" { // pre-set, so no derivation
				t.Errorf("unexpected client_net: %q", act.CommonRequest.ClientNet)
			}

			if !act.CommonRequest.Repeating {
				t.Errorf("expected repeating=true")
			}
		}

		// unblock RunLuaPostAction
		act.FinishedChan <- action.Done{}
		close(done)
	}()

	args := corepkg.PostActionArgs{
		Context:       &lualib.Context{},
		HTTPRequest:   nil,
		ParentSpan:    trace.SpanContextFromContext(context.Background()),
		StatusMessage: "status-1",
		Request: lualib.CommonRequest{
			Session:   "guid-123",
			ClientIP:  "192.0.2.10",
			Protocol:  "imap",
			ClientNet: "10.0.0.0/24", // set to avoid BF derivation path
			Repeating: true,
		},
	}

	auth := corepkg.NewAuthStateFromContextWithDeps(nil, corepkg.AuthDeps{
		Cfg: config.GetFile(),
	}).(*corepkg.AuthState)
	auth.RunLuaPostAction(args)

	<-done
}
