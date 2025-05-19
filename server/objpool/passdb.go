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

// PassDBResultPoolable is an interface for objects that can be pooled in the PassDBResultPool
// Objects implementing this interface can be put in the PassDBResultPool
type PassDBResultPoolable interface {
	Resettable
	IsPassDBResult() bool
}

// PassDBResultPool is a pool for objects implementing the PassDBResultPoolable interface
// It provides methods to get and put these objects
type PassDBResultPool struct {
	pool    *Pool
	newFunc func() any
}

// NewPassDBResultPool creates a new PassDBResultPool with the given new function
// The new function is called when the pool is empty and a new object is needed
func NewPassDBResultPool(newFunc func() any) *PassDBResultPool {
	return &PassDBResultPool{
		pool:    NewPool(newFunc),
		newFunc: newFunc,
	}
}

// Get retrieves an object from the pool
// If the pool is empty, a new object is created using the new function
func (p *PassDBResultPool) Get() any {
	return p.pool.Get()
}

// Put returns an object to the pool
// The object is reset before being returned to the pool
func (p *PassDBResultPool) Put(obj any) {
	if obj != nil {
		if poolable, ok := obj.(PassDBResultPoolable); ok && poolable.IsPassDBResult() {
			p.pool.Put(obj)
		}
	}
}
