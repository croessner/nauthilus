// Package main tests server worker setup behavior.
package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

func TestSetupWorkersTreatsWorkerlessBackendsAsNoop(t *testing.T) {
	for _, value := range []string{
		definitions.BackendTestName,
		definitions.BackendRemoteName,
		definitions.BackendPluginName + "(mailde_auth.passdb)",
	} {
		t.Run(value, func(t *testing.T) {
			var backend config.Backend
			if err := backend.Set(value); err != nil {
				t.Fatalf("set backend %q: %v", value, err)
			}

			cfg := &config.FileSettings{
				Server: &config.ServerSection{
					Backends: []*config.Backend{&backend},
				},
			}

			var logs bytes.Buffer

			logger := slog.New(slog.NewTextHandler(&logs, nil))

			setupWorkers(context.Background(), &contextStore{}, cfg, logger, nil, nil)

			if strings.Contains(logs.String(), "Unknown backend") {
				t.Fatalf("backend %q should not be logged as unknown: %s", value, logs.String())
			}
		})
	}
}
