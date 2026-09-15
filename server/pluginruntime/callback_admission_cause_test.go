package pluginruntime

import (
	"context"
	"errors"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestCallbackAdmissionRetainsRejectionCause separates overload from a canceled caller.
func TestCallbackAdmissionRetainsRejectionCause(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*callbackAdmission) context.Context
		want    error
	}{
		{name: "concurrency", prepare: func(a *callbackAdmission) context.Context {
			a.active = a.limit

			return context.Background()
		}, want: errCallbackConcurrencyLimited},
		{name: "rate", prepare: func(a *callbackAdmission) context.Context {
			a.rate.Allow()

			return context.Background()
		}, want: errCallbackRateLimited},
		{name: "canceled", prepare: func(*callbackAdmission) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			return ctx
		}, want: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := newCallbackAdmission(pluginapi.CallbackAdmissionLimits{RequestsPerSecond: 1, MaxConcurrency: 1})
			ctx := test.prepare(a)

			if err := a.acquire(ctx); !errors.Is(err, test.want) {
				t.Fatalf("admission = %v, want %v", err, test.want)
			}
		})
	}
}
