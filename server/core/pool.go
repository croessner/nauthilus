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

package core

import (
	"github.com/croessner/nauthilus/server/objpool"
)

// InitPassDBResultPool initializes the PassDBResultPool in the objpool package
// This function should be called during application initialization
func InitPassDBResultPool() {
	objpool.SetPassDBResultPoolNewFunc(func() any {
		return &PassDBResult{}
	})
}

// GetPassDBResultFromPool retrieves a PassDBResult object from the pool
// If the pool is empty, a new PassDBResult object is created
func GetPassDBResultFromPool() *PassDBResult {
	return objpool.GetPassDBResultPool().Get().(*PassDBResult)
}

// PutPassDBResultToPool returns a PassDBResult object to the pool
// The object is reset before being returned to the pool
func PutPassDBResultToPool(obj *PassDBResult) {
	if obj != nil {
		objpool.GetPassDBResultPool().Put(obj)
	}
}
