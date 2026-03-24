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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"go.opentelemetry.io/otel/trace"
)

func newLuaPostActionTestConfig(t *testing.T) *config.FileSettings {
	bfFeature := &config.Feature{}
	if err := bfFeature.Set(definitions.FeatureBruteForce); err != nil {
		t.Fatalf("Set feature failed: %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			Features: []*config.Feature{bfFeature},
		},
		Lua: &config.LuaSection{
			Actions: []config.LuaAction{
				{ActionType: definitions.LuaActionPostName},
			},
		},
	}
}

func prepareLuaPostActionTest(t *testing.T) *config.FileSettings {
	cfg := newLuaPostActionTestConfig(t)

	config.SetTestFile(cfg)
	corepkg.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())
	_ = action.NewWorker(cfg, log.GetLogger(), rediscli.GetClient(), util.GetDefaultEnvironment())

	return cfg
}

func newLuaPostActionArgs(req *http.Request) corepkg.PostActionArgs {
	return corepkg.PostActionArgs{
		Context:       &lualib.Context{},
		HTTPRequest:   req,
		ParentSpan:    trace.SpanContextFromContext(context.Background()),
		StatusMessage: "status-1",
		Request: lualib.CommonRequest{
			Session:   "guid-123",
			ClientIP:  "192.0.2.10",
			Protocol:  "imap",
			ClientNet: "10.0.0.0/24",
			Repeating: true,
		},
	}
}

func startLuaPostActionReader() (chan *action.Action, chan struct{}) {
	gotAction := make(chan *action.Action, 1)
	stopReader := make(chan struct{})

	go func() {
		select {
		case act := <-action.RequestChan:
			gotAction <- act
			if act != nil {
				act.FinishedChan <- action.Done{}
			}
		case <-stopReader:
		}
	}()

	return gotAction, stopReader
}

func TestRunLuaPostAction_EnqueuesAndCopies(t *testing.T) {
	cfg := prepareLuaPostActionTest(t)

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
			if act.StatusMessage == nil || *act.StatusMessage != "status-1" {
				t.Errorf("status message copy mismatch: %v", act.StatusMessage)
			}

			if act.ClientNet != "10.0.0.0/24" { // pre-set, so no derivation
				t.Errorf("unexpected client_net: %q", act.ClientNet)
			}

			if !act.Repeating {
				t.Errorf("expected repeating=true")
			}
		}

		// unblock RunLuaPostAction
		act.FinishedChan <- action.Done{}
		close(done)
	}()

	auth := corepkg.NewAuthStateFromContextWithDeps(nil, corepkg.AuthDeps{
		Cfg: cfg,
	}).(*corepkg.AuthState)
	auth.RunLuaPostAction(newLuaPostActionArgs(nil))

	<-done
}

func TestRunLuaPostAction_SkipsCanceledHTTPRequest(t *testing.T) {
	cfg := prepareLuaPostActionTest(t)

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest("POST", "/auth", nil).WithContext(reqCtx)

	auth := corepkg.NewAuthStateFromContextWithDeps(nil, corepkg.AuthDeps{
		Cfg: cfg,
	}).(*corepkg.AuthState)
	auth.Request.HTTPClientRequest = req

	gotAction, stopReader := startLuaPostActionReader()

	done := make(chan struct{})

	go func() {
		auth.RunLuaPostAction(newLuaPostActionArgs(req))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("RunLuaPostAction did not return after request cancellation")
	}

	close(stopReader)

	select {
	case act := <-gotAction:
		t.Fatalf("expected no action to be enqueued, got %+v", act)
	default:
	}
}
