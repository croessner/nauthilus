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

package objpool

import (
	"sync"
)

// Resettable is an interface for objects that can be reset
// Objects implementing this interface can be reset to their zero values
// This is useful for objects that are stored in a sync.Pool
type Resettable interface {
	// Reset resets all fields of the object to their zero values
	Reset()
}

// Pool is a generic object pool that manages reusable objects
// It provides methods to get objects from the pool and put them back
type Pool struct {
	pool sync.Pool
}

// NewPool creates a new Pool with the given new function
// The new function is called when the pool is empty and a new object is needed
func NewPool(newFunc func() any) *Pool {
	return &Pool{
		pool: sync.Pool{
			New: newFunc,
		},
	}
}

// Get retrieves an object from the pool
// If the pool is empty, a new object is created using the new function
func (p *Pool) Get() any {
	return p.pool.Get()
}

// Put returns an object to the pool
// If the object implements the Resettable interface, it is reset before being returned to the pool
func (p *Pool) Put(obj any) {
	if resettable, ok := obj.(Resettable); ok {
		resettable.Reset()
	}
	p.pool.Put(obj)
}
