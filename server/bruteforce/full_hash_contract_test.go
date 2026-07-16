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

package bruteforce

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/secret"
)

func TestPasswordHistoryReadsLegacyHashAndWritesFullHash(t *testing.T) {
	cfg := passwordHistoryCommandConfig(0)
	handle := newPasswordHistoryCommandReadHandle("1.2.3.4", false)
	bm := NewBucketManagerWithDeps(t.Context(), passwordHistoryCommandGUID, "1.2.3.4", BucketManagerDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  &passwordHistoryTestRedisClient{readHandle: handle},
	}).WithAccountName(passwordHistoryCommandAccount).WithPassword(secret.New("wrong-password"))
	impl := bm.(*bucketManagerImpl)
	hash := impl.currentPasswordHash()

	if len(hash) != 64 || strings.ToLower(hash) != hash {
		t.Fatalf("password-history write candidate = %q, want lowercase 64-hex", hash)
	}

	candidates := impl.currentPasswordHashCandidates()
	key := impl.getPasswordHistoryRedisSetKey(true)
	handle.exactMembers = map[string]map[string]bool{
		key: {candidates.Legacy(): true, "unrelated-member": true},
	}
	plan := impl.preparePasswordHistoryLoad(handle, false)
	plan.loadCurrentPasswordHistoryMembership()

	if impl.loginAttempts != 1 {
		t.Fatalf("legacy exact membership produced %d attempts, want 1", impl.loginAttempts)
	}

	if len(handle.commands) != 2 || handle.commands[0].member != candidates.Full() || handle.commands[1].member != candidates.Legacy() {
		t.Fatalf("password-history candidates = %#v, want exact full then legacy", handle.commands)
	}
}
