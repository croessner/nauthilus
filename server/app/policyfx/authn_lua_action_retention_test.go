// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const productionAuthnLuaActionFixture = `policy:
  namespaces:
    authn:
      effects:
        lua_action_notify:
          kind: lua_action
          action_type: lua
          script_path: %q
          targets: [{action: authenticate}]
          execution: host_sync
      domain_plans:
        configured:
          checkpoints:
            pre_auth: {providers: []}
            auth_decision: {providers: []}
      policy_sets:
        configured:
          rules:
            - name: configured_action
              checkpoint: auth_decision
              if: {always: true}
              then:
                decision: deny
                obligations: [{id: authn/lua_action_notify}]
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
      plans:
        auth_decision: {policy_sets: [authn/configured]}
`

// TestProductionCoordinatorRetainsGenerationWhenConfiguredAuthnLuaActionBecomesInvalid proves precommit rejection.
func TestProductionCoordinatorRetainsGenerationWhenConfiguredAuthnLuaActionBecomesInvalid(t *testing.T) {
	script := filepath.Join(t.TempDir(), "action.lua")
	if err := os.WriteFile(script, []byte("function nauthilus_call_action(request) return 1 end\n"), 0o600); err != nil {
		t.Fatalf("write valid action: %v", err)
	}

	configured := productionAuthnLuaActionCandidate(t, script)
	store := policyruntime.NewGenerationStore()

	coordinator, err := NewCoordinator(
		store,
		nil,
		&pluginloader.State{},
		unusedTokenFactory,
		unusedThrottlerFactory,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{}, nil
		},
		localization.NewMapCatalog(nil),
		mustStartupCatalog(t, configured, nil),
		mustRestartBaseline(t, configured),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	active := store.Active()
	if active == nil {
		t.Fatal("initial configured action generation is unavailable")
	}

	if err = os.WriteFile(script, []byte("function nauthilus_call_action("), 0o600); err != nil {
		t.Fatalf("write invalid action: %v", err)
	}

	err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 2})
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("Apply(invalid action) error = %v, want candidate rejection", err)
	}

	if store.Active() != active || store.Active().ID() != 1 {
		t.Fatal("invalid configured action replaced the complete active generation")
	}
}

// productionAuthnLuaActionCandidate constructs one production file with a selected configured effect.
func productionAuthnLuaActionCandidate(t *testing.T, script string) *config.FileSettings {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(fmt.Sprintf(productionAuthnLuaActionFixture, script)))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	return &config.FileSettings{Policy: document.Policy}
}
