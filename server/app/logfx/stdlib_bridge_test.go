package logfx

import (
	bytes2 "bytes"
	"context"
	stdlog "log"
	"log/slog"
	"testing"

	"go.uber.org/fx"
)

func TestStdlibBridgeWritesToSlog(t *testing.T) {
	buf := &bytes2.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	app := fx.New(
		fx.Supply(logger),
		fx.Invoke(BridgeStdLog),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := app.Start(startCtx); err != nil {
		t.Fatalf("failed to start app: %v", err)
	}

	stdlog.Print("hello")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), testTimeout)
	defer stopCancel()

	if err := app.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop app: %v", err)
	}

	if got := buf.String(); got == "" {
		t.Fatalf("expected stdlib log output to be bridged")
	}
}
