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

package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// generationLifetime keeps committed resources alive while captured users or detached work exist.
type generationLifetime struct {
	logger       *slog.Logger
	resources    *candidateResourceOwnership
	onRetired    func(error)
	retireCtx    context.Context
	users        uint64
	id           uint64
	mu           sync.Mutex
	retiring     bool
	closeClaimed bool
}

// generationLease releases one captured or derived lifetime use at most once.
type generationLease struct {
	lifetime *generationLifetime
	err      error
	once     sync.Once
}

// newGenerationLifetime constructs one unpublished resource lifetime owner.
func newGenerationLifetime(
	id uint64,
	resources *candidateResourceOwnership,
	logger *slog.Logger,
) *generationLifetime {
	return &generationLifetime{
		logger:    logger,
		resources: resources,
		id:        id,
	}
}

// setRetirementObserver installs the store callback before publication.
func (l *generationLifetime) setRetirementObserver(observer func(error)) {
	if l == nil {
		return
	}

	l.mu.Lock()
	l.onRetired = observer
	l.mu.Unlock()
}

// acquireCapture reserves one request or session use while the generation accepts new callers.
func (l *generationLifetime) acquireCapture() *generationLease {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.retiring || l.closeClaimed {
		return nil
	}

	l.users++

	return &generationLease{lifetime: l}
}

// retain reserves child work derived from an already captured generation.
func (l *generationLifetime) retain() *generationLease {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closeClaimed || l.users == 0 {
		return nil
	}

	l.users++

	return &generationLease{lifetime: l}
}

// release is idempotent for one explicit lease owner.
func (l *generationLease) release() error {
	if l == nil {
		return nil
	}

	l.once.Do(func() {
		l.err = l.lifetime.releaseUse()
	})

	return l.err
}

// releaseUse drops one lifetime count and performs final retirement when required.
func (l *generationLifetime) releaseUse() error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	if l.users == 0 {
		l.mu.Unlock()

		return fmt.Errorf("%w: generation %d lease underflow", ErrInvalidGeneration, l.id)
	}

	l.users--

	shouldClose := l.retiring && l.users == 0 && !l.closeClaimed
	if shouldClose {
		l.closeClaimed = true
	}

	retireCtx := l.retireCtx
	l.mu.Unlock()

	if !shouldClose {
		return nil
	}

	return l.close(retireCtx)
}

// retire prevents new captures and closes resources once the last user releases them.
func (l *generationLifetime) retire(ctx context.Context) error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	if !l.retiring {
		l.retiring = true
		l.retireCtx = retirementGenerationContext(ctx)
	}

	shouldClose := l.users == 0 && !l.closeClaimed
	if shouldClose {
		l.closeClaimed = true
	}

	retireCtx := l.retireCtx
	l.mu.Unlock()

	if !shouldClose {
		return nil
	}

	return l.close(retireCtx)
}

// close disposes generation resources outside lifetime and store locks exactly once.
func (l *generationLifetime) close(ctx context.Context) error {
	err := l.resources.dispose(normalizedGenerationContext(ctx))

	l.mu.Lock()
	observer := l.onRetired
	l.mu.Unlock()

	if err != nil && l.logger != nil {
		l.logger.ErrorContext(
			context.Background(),
			"policy runtime generation retirement failed",
			slog.Uint64("runtime_generation", l.id),
			slog.Any("error", err),
		)
	}

	if observer != nil {
		observer(err)
	}

	return err
}

// WithActive captures one generation lease for the complete callback scope.
func (s *GenerationStore) WithActive(
	ctx context.Context,
	use func(*Generation) error,
) error {
	if s == nil || use == nil {
		return ErrInvalidGeneration
	}

	ctx = normalizedGenerationContext(ctx)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		generation := s.active.Load()
		if generation == nil {
			return ErrGenerationUnavailable
		}

		lease := generation.lifetime.acquireCapture()
		if lease == nil {
			continue
		}

		if s.active.Load() != generation {
			_ = lease.release()

			continue
		}

		return useCapturedGeneration(generation, lease, use)
	}
}

// useCapturedGeneration guarantees release across errors and panics from one caller callback.
func useCapturedGeneration(
	generation *Generation,
	lease *generationLease,
	use func(*Generation) error,
) (err error) {
	defer func() {
		err = errors.Join(err, lease.release())
	}()

	return use(generation)
}

// commit publishes and tracks one complete generation before retiring its predecessor.
// It never holds the store mutex during disposal; the retirement callback locks the store only afterwards.
func (s *GenerationStore) commit(
	_ context.Context,
	previous *Generation,
	next *Generation,
) (bool, error) {
	if s == nil || next == nil || next.lifetime == nil {
		return false, ErrInvalidGeneration
	}

	next.lifetime.setRetirementObserver(func(err error) {
		s.recordRetirement(next, err)
	})

	s.mu.Lock()
	s.initializeLocked()

	if s.shuttingDown {
		s.mu.Unlock()
		next.lifetime.setRetirementObserver(nil)

		return false, ErrGenerationStoreClosed
	}

	if s.active.Load() != previous {
		s.mu.Unlock()
		next.lifetime.setRetirementObserver(nil)

		return false, ErrGenerationChanged
	}

	s.generations[next] = struct{}{}

	if !s.active.CompareAndSwap(previous, next) {
		delete(s.generations, next)
		s.mu.Unlock()
		next.lifetime.setRetirementObserver(nil)

		return false, ErrGenerationChanged
	}

	s.mu.Unlock()

	if previous == nil || previous.lifetime == nil {
		return true, nil
	}

	return true, previous.lifetime.retire(context.Background())
}

// Shutdown rejects new captures, retires all tracked generations, and waits for final users.
func (s *GenerationStore) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}

	ctx = normalizedGenerationContext(ctx)

	s.mu.Lock()
	s.initializeLocked()

	firstShutdown := !s.shuttingDown
	if firstShutdown {
		s.shuttingDown = true
		s.active.Store(nil)
	}

	generations := make([]*Generation, 0, len(s.generations))
	for generation := range s.generations {
		generations = append(generations, generation)
	}

	if len(s.generations) == 0 {
		s.completeShutdownLocked()
	}

	done := s.shutdownDone
	s.mu.Unlock()

	for _, generation := range generations {
		go func(current *Generation) {
			_ = current.lifetime.retire(ctx)
		}(generation)
	}

	select {
	case <-done:
		return s.RetirementError()
	default:
	}

	select {
	case <-done:
		return s.RetirementError()
	case <-ctx.Done():
		return newGenerationDrainError(errors.Join(ctx.Err(), s.RetirementError()))
	}
}

// RetirementError returns every generation resource-close failure observed by this store.
func (s *GenerationStore) RetirementError() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return errors.Join(s.retirementErrs...)
}

// initializeLocked prepares zero-value-compatible store tracking under the store mutex.
func (s *GenerationStore) initializeLocked() {
	if s.generations == nil {
		s.generations = make(map[*Generation]struct{})
	}

	if s.shutdownDone == nil {
		s.shutdownDone = make(chan struct{})
	}
}

// recordRetirement removes one closed generation and preserves close failures for shutdown.
func (s *GenerationStore) recordRetirement(generation *Generation, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.generations, generation)

	if err != nil {
		s.retirementErrs = append(s.retirementErrs, fmt.Errorf(
			"%w: generation %d: %w",
			ErrGenerationRetirement,
			generation.ID(),
			err,
		))
	}

	if s.shuttingDown && len(s.generations) == 0 {
		s.completeShutdownLocked()
	}
}

// completeShutdownLocked closes the shared completion signal once under the store mutex.
func (s *GenerationStore) completeShutdownLocked() {
	if s.shutdownComplete {
		return
	}

	s.shutdownComplete = true
	close(s.shutdownDone)
}
