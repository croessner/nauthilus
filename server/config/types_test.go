package config

import (
	"testing"
)

func TestFeatureSet_BackendMonitoringAliasIsRejected(t *testing.T) {
	f := &Feature{}
	if err := f.Set("backend_monitoring"); err == nil {
		t.Fatalf("expected alias to be rejected, got nil error")
	}
}
