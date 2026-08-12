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

package effectsupervisor

import "context"

// ExecutableWork is the internal adapter seam shared by established host post-actions.
type ExecutableWork interface {
	Validate() error
	Execute(context.Context) Result
	Cleanup()
}

type executableProvider struct{}

// NewExecutableProvider creates the adapter for already captured host work.
func NewExecutableProvider() Provider {
	return executableProvider{}
}

// Capture validates that the caller supplied one immutable executable owner.
func (executableProvider) Capture(ctx context.Context, work Work) (Work, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	executable, ok := work.(ExecutableWork)
	if !ok || executable == nil {
		return nil, ErrInvalidWork
	}

	if err := executable.Validate(); err != nil {
		return nil, err
	}

	return executable, nil
}

// Execute delegates one invocation to the captured host work owner.
func (executableProvider) Execute(ctx context.Context, work Work) Result {
	return work.(ExecutableWork).Execute(ctx)
}

// Release delegates idempotent resource cleanup to the captured work owner.
func (executableProvider) Release(work Work) {
	work.(ExecutableWork).Cleanup()
}
