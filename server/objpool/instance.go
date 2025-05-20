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
	"fmt"
	"sync"
)

var (
	// passDBResultPoolInstance is the global instance of PassDBResultPool
	passDBResultPoolInstance *PassDBResultPool

	// passDBResultPoolOnce ensures the global instance is created only once
	passDBResultPoolOnce sync.Once
)

// SetPassDBResultPoolNewFunc sets the new function for the global PassDBResultPool instance
// This function must be called before GetPassDBResultPool is called for the first time
// It is typically called during application initialization
func SetPassDBResultPoolNewFunc(newFunc func() interface{}) {
	passDBResultPoolOnce.Do(func() {
		passDBResultPoolInstance = NewPassDBResultPool(newFunc)
	})
}

// GetPassDBResultPool returns the global PassDBResultPool instance
// It panics if SetPassDBResultPoolNewFunc has not been called before
func GetPassDBResultPool() *PassDBResultPool {
	if passDBResultPoolInstance == nil {
		panic(fmt.Errorf("passDBResultPoolInstance is nil, call SetPassDBResultPoolNewFunc first"))
	}
	return passDBResultPoolInstance
}
