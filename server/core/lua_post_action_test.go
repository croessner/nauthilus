package core_test

import (
	"testing"

	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
)

func TestRunLuaPostAction_EnqueuesAndCopies(t *testing.T) {
	// Initialize action channel
	_ = action.NewWorker()

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
		StatusMessage: "status-1",
		Request: lualib.CommonRequest{
			Session:   "guid-123",
			ClientIP:  "192.0.2.10",
			Protocol:  "imap",
			ClientNet: "10.0.0.0/24", // set to avoid BF derivation path
			Repeating: true,
		},
	}

	corepkg.RunLuaPostAction(args)

	<-done
}
