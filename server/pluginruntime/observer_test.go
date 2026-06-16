package pluginruntime

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestOperationalObserverLogsBoundedPluginCallFields(t *testing.T) {
	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	observer := NewOperationalObserver(logger, WithOperationalObserverMetrics(nil))

	observer.ObservePluginCall(CallRecord{
		Err:            errors.New("database failed with password=secret"),
		Duration:       25 * time.Millisecond,
		ModuleName:     "geoip",
		ComponentName:  "environment",
		ExtensionPoint: "environment_source",
		Method:         "Evaluate",
	})

	line := buf.String()
	if !strings.Contains(line, `"plugin_module":"geoip"`) ||
		!strings.Contains(line, `"plugin_component":"environment"`) ||
		!strings.Contains(line, `"plugin_result":"error"`) {
		t.Fatalf("observer log did not include bounded plugin fields: %s", line)
	}

	if strings.Contains(line, "password=secret") || strings.Contains(line, "database failed") {
		t.Fatalf("observer log leaked raw plugin error: %s", line)
	}
}

func TestHostGoLogsPanicWithoutRecoveredValue(t *testing.T) {
	var buf bytes.Buffer

	host := NewHost(WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host.Go(ctx, "worker", func(context.Context) error {
		panic("panic contains password=secret")
	})
	host.WaitWorkers()

	line := buf.String()
	if !strings.Contains(line, "plugin worker panicked") {
		t.Fatalf("worker panic log missing: %s", line)
	}

	if strings.Contains(line, "password=secret") {
		t.Fatalf("worker panic log leaked recovered value: %s", line)
	}
}

func TestHostGoLogsWorkerErrorWithoutRawValue(t *testing.T) {
	var buf bytes.Buffer

	host := NewHost(WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host.Go(ctx, "worker", func(context.Context) error {
		return errors.New("worker failed with password=secret")
	})
	host.WaitWorkers()

	line := buf.String()
	if !strings.Contains(line, "plugin worker stopped with error") {
		t.Fatalf("worker error log missing: %s", line)
	}

	if strings.Contains(line, "password=secret") || strings.Contains(line, "worker failed") {
		t.Fatalf("worker error log leaked raw error: %s", line)
	}
}
