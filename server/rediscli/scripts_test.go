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

import (
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

// resetScriptsCache clears the script SHA cache between tests.
func resetScriptsCache() {
	scriptsMutex.Lock()
	defer scriptsMutex.Unlock()

	clear(scripts)
}

func TestInvalidateScript(t *testing.T) {
	tests := []struct {
		name       string
		preload    map[string]string
		invalidate string
		wantGone   bool
	}{
		{
			name:       "removes existing entry",
			preload:    map[string]string{"TestScript": "abc123"},
			invalidate: "TestScript",
			wantGone:   true,
		},
		{
			name:       "no-op for missing entry",
			preload:    map[string]string{"Other": "xyz"},
			invalidate: "DoesNotExist",
			wantGone:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetScriptsCache()

			scriptsMutex.Lock()
			for k, v := range tt.preload {
				scripts[k] = v
			}
			scriptsMutex.Unlock()

			InvalidateScript(tt.invalidate)

			scriptsMutex.RLock()
			_, exists := scripts[tt.invalidate]
			scriptsMutex.RUnlock()

			assert.False(t, exists, "script should be gone from cache after InvalidateScript")
		})
	}
}

func TestGetReadHandles_TestClient(t *testing.T) {
	tc := &testClient{client: nil}
	handles := tc.GetReadHandles()

	assert.Nil(t, handles, "testClient.GetReadHandles should return nil")
}

func TestGetReadHandles_RedisClient(t *testing.T) {
	tests := []struct {
		name        string
		writeHandle redis.UniversalClient
		readHandles map[string]redis.UniversalClient
		wantLen     int
	}{
		{
			name:        "nil read handles returns nil",
			writeHandle: redis.NewClient(&redis.Options{}),
			readHandles: nil,
			wantLen:     0,
		},
		{
			name:        "single read handle same as write excluded",
			writeHandle: nil,
			readHandles: nil,
			wantLen:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clt := &redisClient{
				writeHandle: tt.writeHandle,
				readHandle:  tt.readHandles,
			}

			handles := clt.GetReadHandles()

			if tt.wantLen == 0 {
				assert.Empty(t, handles)
			} else {
				assert.Len(t, handles, tt.wantLen)
			}

			// Clean up
			if tt.writeHandle != nil {
				tt.writeHandle.Close()
			}
		})
	}
}

func TestGetReadHandles_ExcludesWriteHandle(t *testing.T) {
	// The write handle should be excluded from the read handles list.
	writeClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	readClient := redis.NewClient(&redis.Options{Addr: "localhost:6380"})

	defer writeClient.Close()
	defer readClient.Close()

	clt := &redisClient{
		writeHandle: writeClient,
		readHandle: map[string]redis.UniversalClient{
			"localhost:6379": writeClient, // same as write
			"localhost:6380": readClient,  // distinct replica
		},
	}

	handles := clt.GetReadHandles()

	assert.Len(t, handles, 1, "should exclude the write handle from read handles")
	assert.Equal(t, readClient, handles[0], "returned handle should be the distinct read client")
}
