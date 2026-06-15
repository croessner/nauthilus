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

// UploadedScript stores the Redis SHA and original Lua source for a named custom script.
type UploadedScript struct {
	// Source is the Lua source used to restore Redis script-cache state after NOSCRIPT.
	Source string

	// SHA1 is the Redis script hash returned by SCRIPT LOAD.
	SHA1 string
}

// Uploads is a concurrency-safe registry for named custom Redis Lua scripts.
type Uploads struct {
	// scripts stores upload-script names with their associated SHA-1 hash and source.
	scripts map[string]UploadedScript

	// mu provides mutual exclusion to ensure that concurrent access to the scripts map is synchronized.
	mu sync.RWMutex
}

// Set stores the script metadata for a named upload in a concurrency-safe manner.
func (u *Uploads) Set(uploadScriptName string, sha1 string, source string) {
	if uploadScriptName == "" || sha1 == "" || source == "" {
		return
	}

	u.mu.Lock()

	defer u.mu.Unlock()

	u.scripts[uploadScriptName] = UploadedScript{
		Source: source,
		SHA1:   sha1,
	}
}

// Get retrieves script metadata associated with the given upload script name.
func (u *Uploads) Get(uploadScriptName string) (UploadedScript, bool) {
	u.mu.RLock()

	defer u.mu.RUnlock()

	uploadedScript, okay := u.scripts[uploadScriptName]

	return uploadedScript, okay
}

// scriptsRepository manages custom script uploads with their associated SHA-1 hashes and sources.
var scriptsRepository = &Uploads{
	scripts: make(map[string]UploadedScript),
}

// defaultHashTag is the default hash tag used for Redis Cluster keys in Lua scripts
// Using a different hash tag than the one in rediscli to distribute load across nodes
var defaultHashTag = "{lua-nauthilus}"
