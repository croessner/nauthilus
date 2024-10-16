package connmgr

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	lua "github.com/yuin/gopher-lua"
)

func TestConnectionManager(t *testing.T) {
	ctx := context.Background()
	config.LoadableConfig = &config.File{Server: &config.ServerSection{DNS: config.DNS{Timeout: 100 * time.Millisecond}}}
	manager = GetConnectionManager()

	t.Run("Register and GetCount", func(t *testing.T) {
		manager.Register(ctx, "127.0.0.1:8000", "local", "test")

		_, ok := manager.GetCount("127.0.0.1:8000")
		if !ok {
			t.Errorf("Failed to register and retrieve target")
		}
	})

	t.Run("Register existing", func(t *testing.T) {
		manager.Register(ctx, "127.0.0.1:8000", "local", "test")

		target := "127.0.0.1:8000"

		manager.Register(ctx, target, "remote", "test")

		count, ok := manager.GetCount(target)
		if !ok || count != 0 {
			t.Errorf("Failed to prevent duplicate registration")
		}
	})

	t.Run("GetCount non-existing", func(t *testing.T) {
		_, ok := manager.GetCount("non-existing")
		if ok {
			t.Errorf("Failed to return false for non-existing target")
		}
	})

	t.Run("Lua Register and GetCount", func(t *testing.T) {
		L := lua.NewState()

		defer L.Close()

		L.SetGlobal("register", L.NewFunction(manager.luaRegisterTarget(ctx)))
		L.SetGlobal("count", L.NewFunction(manager.luaCountOpenConnections))

		if err := L.DoString(`register("127.0.0.1:9000", "remote", "test")`); err != nil {
			t.Errorf("Lua register failed: %v", err)
		}

		if err := L.DoString(`
		    count = count("127.0.0.1:9000")
		    if type(count) ~= 'number' then
			  error('Count is not a number')
		    end
    `); err != nil {
			t.Errorf("Lua count failed: %v", err)
		}
	})
}

func TestStartTicker(t *testing.T) {
	manager = GetConnectionManager()
	done := make(chan struct{})

	go func() {
		manager.StartTicker(100 * time.Millisecond)

		close(done)
	}()

	select {
	case <-done:
		t.Errorf("StartTicker ended too soon")
	case <-time.After(500 * time.Millisecond):
		// Test passed if still running after 500ms
	}
}
