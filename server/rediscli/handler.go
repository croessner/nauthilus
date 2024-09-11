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

package rediscli

import "github.com/redis/go-redis/v9"

var (
	// WriteHandle is a variable of type `redis.UniversalClient` that represents the system wide redis pool (writes).
	WriteHandle redis.UniversalClient //nolint:gochecknoglobals // System wide redis pool

	// ReadHandle is a variable of type `redis.UniversalClient` that represents the system wide redis pool (reads).
	ReadHandle redis.UniversalClient //nolint:gochecknoglobals // System wide redis pool
)
