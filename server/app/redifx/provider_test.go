package redifx

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
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
