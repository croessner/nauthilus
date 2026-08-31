package redifx

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
)

func TestNewClientReturnsClient(t *testing.T) {
	// Use a test client to keep the test hermetic.
	config.SetTestFile(&config.FileSettings{})

	db, _ := redismock.NewClientMock()
	clt := rediscli.NewTestClient(db)

	managed := NewManagedClient(clt)
	if managed == nil {
		t.Fatalf("expected managed client")
	}

	if managed.GetWriteHandle() == nil {
		t.Fatalf("expected write handle")
	}
}

func TestManagedClientRetainsActiveClientWhenSealedTLSIsInvalid(t *testing.T) {
	db, _ := redismock.NewClientMock()
	managed := NewManagedClient(rediscli.NewTestClient(db))

	caPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write invalid Redis CA: %v", err)
	}

	candidate := &config.FileSettings{Server: &config.ServerSection{}}

	candidate.Server.Redis.TLS = config.TLS{Enabled: true, CAFile: caPath}
	if _, err := config.EnsureArtifactSnapshot(candidate); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := managed.Rebuild(candidate, logger); err == nil {
		t.Fatal("Rebuild() error = nil, want invalid sealed Redis TLS rejection")
	}

	if managed.GetWriteHandle() != db {
		t.Fatal("Rebuild() replaced the active Redis client after candidate failure")
	}
}
