// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"sync"
)

type geoDatabaseOwner struct {
	databases geoDatabases
	drained   chan struct{}
	readers   int
	retired   bool
	closed    bool
	mu        sync.Mutex
}

type geoDatabaseLease struct {
	owner     *geoDatabaseOwner
	databases geoDatabases
	once      sync.Once
}

// newGeoDatabaseOwner creates one lifecycle owner for an immutable database pair.
func newGeoDatabaseOwner(databases geoDatabases) *geoDatabaseOwner {
	return &geoDatabaseOwner{databases: databases, drained: make(chan struct{})}
}

// Ready reports whether the owner can provide a primary lookup database.
func (o *geoDatabaseOwner) Ready() bool {
	if o == nil {
		return false
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	return !o.retired && o.databases.Ready()
}

// Acquire reserves the database pair until the returned lease is released.
func (o *geoDatabaseOwner) Acquire() (*geoDatabaseLease, bool) {
	if o == nil {
		return nil, false
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if o.retired || !o.databases.Ready() {
		return nil, false
	}

	o.readers++

	return &geoDatabaseLease{owner: o, databases: o.databases}, true
}

// Retire prevents new leases and closes the databases after active readers leave.
func (o *geoDatabaseOwner) Retire() <-chan struct{} {
	if o == nil {
		drained := make(chan struct{})
		close(drained)

		return drained
	}

	o.mu.Lock()
	o.retired = true
	databases, closeNow := o.closeCandidateLocked()
	drained := o.drained
	o.mu.Unlock()

	if closeNow {
		closeDatabases(databases)
		close(drained)
	}

	return drained
}

// WaitRetired waits until every lease is released or the context is canceled.
func (o *geoDatabaseOwner) WaitRetired(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	drained := o.Retire()

	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release relinquishes one active lookup lease exactly once.
func (l *geoDatabaseLease) Release() {
	if l == nil || l.owner == nil {
		return
	}

	l.once.Do(l.owner.release)
}

// release closes a retired owner after its final active lookup leaves.
func (o *geoDatabaseOwner) release() {
	o.mu.Lock()
	if o.readers > 0 {
		o.readers--
	}

	databases, closeNow := o.closeCandidateLocked()
	drained := o.drained
	o.mu.Unlock()

	if closeNow {
		closeDatabases(databases)
		close(drained)
	}
}

// closeCandidateLocked claims the database close operation when retirement is drained.
func (o *geoDatabaseOwner) closeCandidateLocked() (geoDatabases, bool) {
	if !o.retired || o.readers != 0 || o.closed {
		return geoDatabases{}, false
	}

	o.closed = true

	return o.databases, true
}
