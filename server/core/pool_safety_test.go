package core

import (
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/stretchr/testify/assert"
)

func TestCommonRequestPoolSafety(t *testing.T) {
	// Hole ein Objekt, setze Felder, gib es zurück
	cr1 := lualib.GetCommonRequest()
	cr1.Username = "user1"
	cr1.Service = "service1"
	lualib.PutCommonRequest(cr1)

	// Hole ein neues Objekt (sollte das gleiche sein)
	cr2 := lualib.GetCommonRequest()
	assert.Equal(t, "", cr2.Username, "Username should be reset")
	assert.Equal(t, "", cr2.Service, "Service should be reset")

	// Parallel-Test für Race Conditions und Datenmischung
	var wg sync.WaitGroup

	numGoroutines := 100
	wg.Add(numGoroutines)

	for range numGoroutines {
		go func() {
			defer wg.Done()

			for range 100 {
				cr := lualib.GetCommonRequest()
				assert.Equal(t, "", cr.Username)
				cr.Username = "test"
				lualib.PutCommonRequest(cr)
			}
		}()
	}

	wg.Wait()
}

func TestPassDBResultPoolSafety(t *testing.T) {
	InitPassDBResultPool()

	// Hole ein Objekt, setze Felder, gib es zurück
	res1 := GetPassDBResultFromPool()
	res1.Authenticated = true
	res1.Account = "acc1"
	PutPassDBResultToPool(res1)

	// Hole ein neues Objekt
	res2 := GetPassDBResultFromPool()
	assert.False(t, res2.Authenticated, "Authenticated should be reset")
	assert.Equal(t, "", res2.Account, "Account should be reset")

	PutPassDBResultToPool(res2)
}
