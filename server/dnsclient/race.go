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

package dnsclient

import (
	"context"
	"errors"
	"net"
	"time"
)

// errTextContextEnded starts the text of a lookup that ended with its context, so it is never mistaken for a
// resolver answer such as an i/o timeout.
const errTextContextEnded = "DNS lookup context ended: "

// lookupFunc performs one query through the given resolver.
type lookupFunc[T any] func(ctx context.Context, resolver *net.Resolver) (T, error)

// attemptResult carries the outcome of one attempt.
type attemptResult[T any] struct {
	value T
	err   error
}

// lookupRace runs overlapping attempts of one lookup. A later attempt is
// started while earlier ones keep running, and the first definitive answer wins.
type lookupRace[T any] struct {
	ctx       context.Context
	lookup    lookupFunc[T]
	results   chan attemptResult[T]
	lastErr   error
	name      string
	resolvers []*net.Resolver
	started   int
	pending   int
}

// newLookupRace prepares a race over the given resolvers, one per attempt.
func newLookupRace[T any](ctx context.Context, name string, resolvers []*net.Resolver, lookup lookupFunc[T]) *lookupRace[T] {
	return &lookupRace[T]{
		ctx:       ctx,
		lookup:    lookup,
		results:   make(chan attemptResult[T], len(resolvers)),
		name:      name,
		resolvers: resolvers,
	}
}

// run starts the first attempt and adds one more per interval until an answer
// arrives, all attempts failed, or the context ends.
func (r *lookupRace[T]) run(interval time.Duration) (T, error) {
	var zero T

	r.start()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.start()
		case result := <-r.results:
			r.pending--

			if result.err == nil || !isTransient(result.err) {
				return result.value, result.err
			}

			r.lastErr = result.err

			if r.pending == 0 && !r.start() {
				return zero, r.lastErr
			}
		case <-r.ctx.Done():
			return zero, r.contextError()
		}
	}
}

// start launches the next attempt and reports whether one was left to launch.
func (r *lookupRace[T]) start() bool {
	if r.started >= len(r.resolvers) || r.ctx.Err() != nil {
		return false
	}

	resolver := r.resolvers[r.started]
	r.started++
	r.pending++

	go func() {
		value, err := r.lookup(r.ctx, resolver)
		r.results <- attemptResult[T]{value: value, err: err}
	}()

	return true
}

// contextError describes an expired or cancelled lookup budget as a DNS error. The text names the context end and,
// when one was set, its cause; errors.Is reaches both the standard context error and the cause. Only an expired
// deadline is a timeout, so the retry classification follows ctx.Err() and never a custom cause.
func (r *lookupRace[T]) contextError() error {
	err := r.ctx.Err()
	cause := context.Cause(r.ctx)
	message := errTextContextEnded + err.Error()
	unwrapped := err

	// errors.Is compares only comparable values, so an arbitrary cause type cannot panic here. Without a custom cause
	// context.Cause returns ctx.Err() itself, which is not repeated.
	if cause != nil && !errors.Is(err, cause) {
		message += "; cause: " + cause.Error()
		unwrapped = errors.Join(err, cause)
	}

	return &net.DNSError{UnwrapErr: unwrapped, Err: message, Name: r.name,
		IsTimeout: errors.Is(err, context.DeadlineExceeded)}
}
