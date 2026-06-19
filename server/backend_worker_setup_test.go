// Package main tests server worker setup behavior.
package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

func TestSetupWorkersTreatsTestBackendAsNoop(t *testing.T) {
	var backend config.Backend
	if err := backend.Set(definitions.BackendTestName); err != nil {
		t.Fatalf("set test backend: %v", err)
	}

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Backends: []*config.Backend{&backend},
		},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	setupWorkers(context.Background(), &contextStore{}, nil, cfg, logger, nil, nil)

	if strings.Contains(logs.String(), "Unknown backend") {
		t.Fatalf("test backend should not be logged as unknown: %s", logs.String())
	}
}
