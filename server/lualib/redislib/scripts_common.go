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

package redislib

import (
	"sync"
)

// Uploads is a concurrency-safe type for managing script uploads, utilizing a map to store key-value pairs securely.
type Uploads struct {
	// scripts stores key-value pairs where the key is the name of the upload script, and the value is its associated SHA-1 hash.
	scripts map[string]string

	// mu provides mutual exclusion to ensure that concurrent access to the scripts map is synchronized.
	mu sync.Mutex
}

// Set stores the provided SHA-1 hash associated with the given upload script name in a concurrency-safe manner.
func (u *Uploads) Set(uploadScriptName string, sha1 string) {
	u.mu.Lock()

	defer u.mu.Unlock()

	u.scripts[uploadScriptName] = sha1
}

// Get retrieves the SHA-1 hash associated with the given upload script name in a concurrency-safe manner.
func (u *Uploads) Get(uploadScriptName string) string {
	u.mu.Lock()

	defer u.mu.Unlock()

	if sha1, okay := u.scripts[uploadScriptName]; okay {
		return sha1
	}

	return ""
}

// scriptsRepository is an instance of the Uploads struct that manages script uploads with their associated SHA-1 hashes.
var scriptsRepository = &Uploads{
	scripts: make(map[string]string),
}

// defaultHashTag is the default hash tag used for Redis Cluster keys in Lua scripts
// Using a different hash tag than the one in rediscli to distribute load across nodes
var defaultHashTag = "{lua-nauthilus}"
