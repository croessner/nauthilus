package pluginruntime

import (
	"context"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
)

// TestAuthnCapturePreservesBuiltinControls reproduces host control sets crossing the native request boundary.
func TestAuthnCapturePreservesBuiltinControls(t *testing.T) {
	for _, detached := range []bool{false, true} {
		t.Run(map[bool]string{false: "synchronous", true: "post_action"}[detached], func(t *testing.T) {
			controls := config.NewStringSet()
			controls.Set(definitions.ControlBruteForce)
			controls.Set(definitions.ControlRBL)

			auth := &core.AuthState{Runtime: core.AuthRuntime{Context: lualib.NewContext()}}
			auth.Runtime.Context.Set(definitions.LuaCtxBuiltin, controls)

			capture, err := NewAuthnRequestRuntime().Capture(context.Background(), core.AuthnNativeCaptureInput{
				Auth: auth, Detached: detached,
			})
			if err != nil {
				t.Fatal(err)
			}

			got := capture.Runtime.Snapshot()[definitions.LuaCtxBuiltin]
			if !reflect.DeepEqual(got, []any{definitions.ControlBruteForce, definitions.ControlRBL}) {
				t.Fatalf("controls = %#v", got)
			}

			if _, ok := auth.Runtime.Context.Get(definitions.LuaCtxBuiltin).(config.StringSet); !ok {
				t.Fatal("capture changed the host-owned context")
			}
		})
	}
}
