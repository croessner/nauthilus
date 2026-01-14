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
	"sync"
	"time"
)

// stopLoop contains the common logic to gracefully stop a looping service.
//
// It stops the ticker, cancels the context and waits for all goroutines to
// finish, attempting to honor the provided stop deadline.
func stopLoop(
	mu *sync.Mutex,
	running *bool,
	cancelPtr *context.CancelFunc,
	tickerPtr **time.Ticker,
	ctxPtr *context.Context,
	wg *sync.WaitGroup,
	stopCtx context.Context,
) error {
	mu.Lock()

	if !*running {
		mu.Unlock()

		return nil
	}

	cancel := *cancelPtr
	ticker := *tickerPtr
	*running = false
	*cancelPtr = nil
	*ctxPtr = nil
	*tickerPtr = nil

	mu.Unlock()

	if ticker != nil {
		ticker.Stop()
	}

	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-stopCtx.Done():
		return stopCtx.Err()
	}
}
