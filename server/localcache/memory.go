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

package localcache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

// LocalCache is a cache object with a default expiration duration of 5 minutes
// and a cleanup interval of 10 minutes.
var LocalCache = cache.New(5*time.Minute, 10*time.Minute)
