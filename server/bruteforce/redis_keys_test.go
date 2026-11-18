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
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// TestRWPAllowanceKeyFollowsLoginIdentity pins the writer format the user flush rebuilds from stored
// account-mapping fields: named logins use `<username>|<protocol>|<oidc_cid>`, others the account name.
func TestRWPAllowanceKeyFollowsLoginIdentity(t *testing.T) {
	cases := []struct {
		name     string
		clientIP string
		username string
		oidcCID  string
		ipv6CIDR uint
		want     string
	}{
		{name: "named login", clientIP: "192.0.2.10", username: "alice", want: "nt_bf:rwp:allow:192.0.2.10:alice|imap|"},
		{name: "oidc client", clientIP: "192.0.2.10", username: "alice", oidcCID: "client-a", want: "nt_bf:rwp:allow:192.0.2.10:alice|imap|client-a"},
		{name: "account fallback", clientIP: "192.0.2.10", want: "nt_bf:rwp:allow:192.0.2.10:account"},
		{name: "scoped ipv6", clientIP: "2001:db8:1:2::7", username: "alice", ipv6CIDR: 48, want: "nt_bf:rwp:allow:2001:db8:1::/48:alice|imap|"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := passwordHistoryCommandConfig(tc.ipv6CIDR)
			bm := NewBucketManagerWithDeps(context.Background(), "rwp-key-guid", tc.clientIP, BucketManagerDeps{
				Cfg:    cfg,
				Logger: log.GetLogger(),
			}).
				WithUsername(tc.username).
				WithProtocol("imap").
				WithOIDCCID(tc.oidcCID).
				WithPassword(secret.New("wrong-password")).
				WithAccountName("account").(*bucketManagerImpl)

			got, passwordHash := bm.buildRWPKeyAndHash()
			if got != tc.want || passwordHash == "" {
				t.Fatalf("RWP key = %q (hash set: %t), want %q", got, passwordHash != "", tc.want)
			}
		})
	}
}

// TestPasswordHistoryRedisKeyFormats pins the account-scoped and address-wide password-history formats.
func TestPasswordHistoryRedisKeyFormats(t *testing.T) {
	if got := PasswordHistoryRedisKey("nt_", "alice", "192.0.2.10"); got != "nt_pw_hist:{alice:192.0.2.10}:alice:192.0.2.10" {
		t.Fatalf("account-scoped key = %q", got)
	}

	if got := PasswordHistoryRedisKey("nt_", "", "192.0.2.10"); got != "nt_pw_hist:{192.0.2.10}:192.0.2.10" {
		t.Fatalf("address-wide key = %q", got)
	}
}
