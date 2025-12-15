package redifx

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
	redismock "github.com/go-redis/redismock/v9"
)

func TestNewClientReturnsClient(t *testing.T) {
	// Use a test client to keep the test hermetic.
	config.SetTestFile(&config.FileSettings{})

	db, _ := redismock.NewClientMock()
	rediscli.NewTestClient(db)

	clt := NewClient()
	if clt == nil {
		t.Fatalf("expected client")
	}
}
