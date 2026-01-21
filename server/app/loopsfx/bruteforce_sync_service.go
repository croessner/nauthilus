// Copyright (C) 2024 Christian Rößner
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

package loopsfx

import (
	"context"
	"log/slog"
	"sync"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/redifx"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"

	jsoniter "github.com/json-iterator/go"
	"go.opentelemetry.io/otel/attribute"
)

// BruteForceSyncService is a background service that listens for global brute-force block events
// via Redis Pub/Sub and updates the local L1 micro-cache accordingly.
type BruteForceSyncService struct {
	cfgProvider configfx.Provider
	redisClient redifx.Client
	ctx         context.Context
	wg          sync.WaitGroup
	logger      *slog.Logger
	mu          sync.Mutex
	cancel      context.CancelFunc
	running     bool
}

// NewBruteForceSyncService initializes and returns a BruteForceSyncService.
func NewBruteForceSyncService(cfgProvider configfx.Provider, logger *slog.Logger, redisClient redifx.Client) *BruteForceSyncService {
	return &BruteForceSyncService{
		cfgProvider: cfgProvider,
		logger:      logger,
		redisClient: redisClient,
	}
}

// Start begins the Pub/Sub listener loop.
func (s *BruteForceSyncService) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	snap := s.cfgProvider.Current()
	if snap.File == nil || !snap.File.HasFeature(definitions.FeatureBruteForce) {
		return nil
	}

	ctx, cancel := context.WithCancel(parent)
	s.ctx = ctx
	s.cancel = cancel
	s.running = true

	s.wg.Add(1)
	go s.listenLoop(ctx)

	return nil
}

// listenLoop subscribes to the brute-force block channel and handles incoming messages.
func (s *BruteForceSyncService) listenLoop(ctx context.Context) {
	defer s.wg.Done()

	level.Info(s.logger).Log(definitions.LogKeyMsg, "Starting brute-force sync listener", "channel", definitions.RedisBFBlocksChannel)

	pubsub := s.redisClient.GetReadHandle().Subscribe(ctx, definitions.RedisBFBlocksChannel)
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			level.Info(s.logger).Log(definitions.LogKeyMsg, "Stopping brute-force sync listener")
			return
		case msg, ok := <-ch:
			if !ok {
				level.Warn(s.logger).Log(definitions.LogKeyMsg, "Brute-force sync channel closed")
				return
			}
			s.handleMessage(msg.Payload)
		}
	}
}

// handleMessage unmarshals and applies a block event to the local cache.
func (s *BruteForceSyncService) handleMessage(payload string) {
	tr := monittrace.New("nauthilus/sync")
	_, sp := tr.Start(s.ctx, "sync.handle_message", attribute.Int("payload_len", len(payload)))
	defer sp.End()

	var msg bruteforce.BlockMessage
	if err := jsoniter.ConfigFastest.Unmarshal([]byte(payload), &msg); err != nil {
		level.Error(s.logger).Log(definitions.LogKeyMsg, "Failed to unmarshal brute-force sync message", definitions.LogKeyError, err)
		return
	}

	sp.SetAttributes(
		attribute.String("key", msg.Key),
		attribute.String("rule", msg.Rule),
		attribute.Bool("block", msg.Block),
	)

	bruteforce.UpdateL1Cache(s.ctx, msg.Key, msg.Block, msg.Rule)
}

// Stop terminates the sync service and waits for the listener to exit.
func (s *BruteForceSyncService) Stop(stopCtx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	cancel := s.cancel
	s.running = false
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-stopCtx.Done():
		return stopCtx.Err()
	}
}
