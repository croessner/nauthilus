// Copyright (C) 2026 Christian Roessner
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

// Package effectsupervisor owns accepted host post-actions until execution and cleanup complete.
package effectsupervisor

import (
	"errors"
	"sync"
)

var errInvalidBoundary = errors.New("invalid application-response finalization boundary")

// Boundary identifies the server-observable application-response finalization point.
type Boundary string

const (
	// BoundaryHTTPCommit opens after the HTTP handler returns and response state is committed.
	BoundaryHTTPCommit Boundary = "http_commit"

	// BoundaryGRPCUnaryReturn opens after the unary handler and interceptor chain return.
	BoundaryGRPCUnaryReturn Boundary = "grpc_unary_return"
)

// FinalizationGate delays accepted work until an application response is immutable.
type FinalizationGate interface {
	Done() <-chan struct{}
	Boundary() Boundary
}

// Gate is an idempotent application-response finalization signal.
type Gate struct {
	done     chan struct{}
	once     sync.Once
	boundary Boundary
}

// NewGate constructs a typed application-response finalization gate.
func NewGate(boundary Boundary) (*Gate, error) {
	if !validBoundary(boundary) {
		return nil, errInvalidBoundary
	}

	return &Gate{
		done:     make(chan struct{}),
		boundary: boundary,
	}, nil
}

// Done closes when accepted post-action execution may begin.
func (g *Gate) Done() <-chan struct{} {
	if g == nil {
		return nil
	}

	return g.done
}

// Boundary returns the precise application-response finalization contract.
func (g *Gate) Boundary() Boundary {
	if g == nil {
		return ""
	}

	return g.boundary
}

// Complete opens the gate exactly once.
func (g *Gate) Complete() {
	if g == nil {
		return
	}

	g.once.Do(func() {
		close(g.done)
	})
}

// validBoundary accepts only the two deliberately distinct transport boundaries.
func validBoundary(boundary Boundary) bool {
	return boundary == BoundaryHTTPCommit || boundary == BoundaryGRPCUnaryReturn
}
