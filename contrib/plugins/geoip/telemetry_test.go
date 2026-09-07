package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type errorCaptureTracer struct {
	pluginapi.Tracer
	errorCaptureSpan
}

type errorTelemetryDatabase struct {
	*lifecycleTestDatabase
}

// Lookup injects a raw database failure at the real provider boundary.
func (errorTelemetryDatabase) Lookup(context.Context, netip.Addr) (geoRecord, bool, error) {
	return geoRecord{}, false, errors.New("database lookup 192.0.2.8 token=secret")
}

func TestGeoIPPolicyErrorRemainsRedactedForParentTelemetry(t *testing.T) {
	plugin := &Plugin{config: moduleConfig{LookupTimeout: time.Second}, databaseOwner: newGeoDatabaseOwner(geoDatabases{
		primary: errorTelemetryDatabase{newLifecycleTestDatabase("DE", false)},
	})}

	result, err := (geoIPLookupService{plugin: plugin}).evaluateClientIP(t.Context(), "192.0.2.8")
	if err != errTelemetryLookup || len(result.Facts) != 0 {
		t.Fatal("provider exported a raw error or partial facts to parent telemetry")
	}
}

type errorCaptureSpan struct {
	noopSpan
	errors []string
}

// Start preserves the raw-error capture boundary of the real tracer interface.
func (t *errorCaptureTracer) Start(ctx context.Context, _ string, _ ...pluginapi.TraceAttribute) (context.Context, pluginapi.Span) {
	return ctx, &t.errorCaptureSpan
}

// RecordError retains the exact text that would reach the configured exporter.
func (s *errorCaptureSpan) RecordError(err error) { s.errors = append(s.errors, err.Error()) }

func TestGeoIPTelemetryRedactsRawLookupErrors(t *testing.T) {
	raw := errors.New("lookup 192.0.2.8 example.test token=secret")
	tracer := &errorCaptureTracer{}

	_, _, err := traceGeoIPLookup(context.Background(), tracer, spanGeoIPPrimaryDatabaseLookup,
		func(context.Context) (int, bool, error) { return 0, false, raw })
	if err != raw {
		t.Fatal("telemetry changed lookup error semantics")
	}

	logger := &recordingPrivacyLogger{}
	(&Plugin{logger: logger}).logError(context.Background(), "geoip database refresh failed", raw)

	text := strings.Join(append(tracer.errors, logger.values...), " ")
	for _, secret := range []string{"192.0.2.8", "example.test", "token=secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("raw lookup detail reached telemetry: %s", secret)
		}
	}
}
