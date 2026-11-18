// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package idp

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	slodomain "github.com/croessner/nauthilus/v4/server/idp/slo"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// sloReadBarrierTimeout bounds how long one reader waits for its peer, so a serialized implementation that
// never lets both readers overlap still finishes.
const sloReadBarrierTimeout = 2 * time.Second

// sloReadBarrierHook holds every first read of one key until a second reader has read it too, which forces
// two concurrent load-modify-store sequences to interleave.
type sloReadBarrierHook struct {
	key     string
	release chan struct{}
	mu      sync.Mutex
	readers int
}

// DialHook keeps dialing unchanged.
func (h *sloReadBarrierHook) DialHook(next redis.DialHook) redis.DialHook { return next }

// ProcessPipelineHook keeps pipelines unchanged.
func (h *sloReadBarrierHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// ProcessHook parks the first two GET calls of the watched key until both have completed.
func (h *sloReadBarrierHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)

		if !strings.EqualFold(cmd.Name(), "get") || len(cmd.Args()) < 2 || cmd.Args()[1] != h.key {
			return err
		}

		h.mu.Lock()
		h.readers++
		readers := h.readers
		h.mu.Unlock()

		switch readers {
		case 2:
			close(h.release)
		case 1:
			select {
			case <-h.release:
			case <-time.After(sloReadBarrierTimeout):
			}
		}

		return err
	}
}

// TestSAMLHandler_applySLOFanoutLogoutResponse_ConcurrentResponsesKeepAllOutcomes proves that two
// LogoutResponses for different participants of one fan-out transaction never overwrite each other's outcome.
func TestSAMLHandler_applySLOFanoutLogoutResponse_ConcurrentResponsesKeepAllOutcomes(t *testing.T) {
	const (
		transactionID = "tx-slo-concurrent"
		requestA      = "id-slo-request-a"
		requestB      = "id-slo-request-b"
		entityA       = "https://sp-a.example.com/saml/metadata"
		entityB       = "https://sp-b.example.com/saml/metadata"
	)

	storage := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = db.Close() })

	handler := NewSAMLHandler(&deps.Deps{
		Cfg:    &mockSAMLCfg{redisPrefix: "test:"},
		Logger: slog.Default(),
		Redis:  rediscli.NewTestClientForHandle(db),
	}, nil)

	transaction := mustIDPFanoutRunningTransaction(t, transactionID, "id-root-concurrent", slodomain.SLOBindingRedirect, entityA, requestA)
	transaction.Participants = append(transaction.Participants, slodomain.Participant{
		EntityID: entityB, RequestID: requestB, Binding: slodomain.SLOBindingRedirect,
	})

	dispatches := []sloFanoutDispatch{{Participant: transaction.Participants[0]}, {Participant: transaction.Participants[1]}}
	if err := handler.storeSLOFanoutTransactionState(t.Context(), transaction, &sloFanoutResult{Dispatches: dispatches}); err != nil {
		t.Fatalf("store fan-out state: %v", err)
	}

	db.AddHook(&sloReadBarrierHook{key: handler.sloFanoutStateKey(transactionID), release: make(chan struct{})})

	var wg sync.WaitGroup

	for _, response := range []*saml.LogoutResponse{
		newSLOFanoutTestLogoutResponse("id-response-a", requestA, entityA, saml.StatusSuccess),
		newSLOFanoutTestLogoutResponse("id-response-b", requestB, entityB, saml.StatusSuccess),
	} {
		wg.Go(func() {
			if _, err := handler.applySLOFanoutLogoutResponse(context.Background(), response, transactionID); err != nil {
				t.Errorf("apply %s: %v", response.InResponseTo, err)
			}
		})
	}

	wg.Wait()

	rawState, err := storage.Get(handler.sloFanoutStateKey(transactionID))
	if err != nil {
		t.Fatalf("load fan-out state: %v", err)
	}

	var state sloFanoutTransactionState
	if err = json.Unmarshal([]byte(rawState), &state); err != nil {
		t.Fatalf("decode fan-out state: %v", err)
	}

	if len(state.Outcomes) != 2 || len(state.Pending) != 0 || state.Transaction.Status != slodomain.SLOStatusDone {
		t.Fatalf("fan-out state lost an outcome: outcomes=%d pending=%d status=%s",
			len(state.Outcomes), len(state.Pending), state.Transaction.Status)
	}
}
