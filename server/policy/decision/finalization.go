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

package decision

import "sync"

const (
	finalizationHTTPCommit    = "http_commit"
	finalizationGRPCUnaryDone = "grpc_unary_return"
)

// EvaluationFinalization is a host-created application-response immutability gate.
type EvaluationFinalization struct {
	state *evaluationFinalizationState
}

type evaluationFinalizationState struct {
	done     chan struct{}
	once     sync.Once
	boundary string
}

// NewEvaluationFinalization constructs one transport-neutral finalization gate.
func NewEvaluationFinalization[T ~string](boundary T) EvaluationFinalization {
	value := string(boundary)
	if value != finalizationHTTPCommit && value != finalizationGRPCUnaryDone {
		return EvaluationFinalization{}
	}

	return EvaluationFinalization{state: &evaluationFinalizationState{done: make(chan struct{}), boundary: value}}
}

// Done closes after the application response becomes immutable.
func (f EvaluationFinalization) Done() <-chan struct{} {
	if f.state == nil {
		return nil
	}

	return f.state.done
}

// Boundary returns the exact application finalization boundary.
func (f EvaluationFinalization) Boundary() string {
	if f.state == nil {
		return ""
	}

	return f.state.boundary
}

// Complete opens the response finalization gate exactly once.
func (f EvaluationFinalization) Complete() {
	if f.state == nil {
		return
	}

	f.state.once.Do(func() {
		close(f.state.done)
	})
}

// Valid reports whether the host selected one supported boundary.
func (f EvaluationFinalization) Valid() bool {
	return f.Done() != nil && (f.Boundary() == finalizationHTTPCommit || f.Boundary() == finalizationGRPCUnaryDone)
}
