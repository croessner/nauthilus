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

package ldappool

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// TestDroppedLDAPReplyLogsRequestSession pins that a reply dropped because the requester stopped listening names
// the request session, so the warning can be correlated with the request log.
func TestDroppedLDAPReplyLogsRequestSession(t *testing.T) {
	setupLDAPPoolTestConfig()

	var buf bytes.Buffer

	owned := &LDAPConnectionImpl{}
	owned.SetState(definitions.LDAPStateBusy)

	pool := newLookupTestPool(t.Context(), definitions.LDAPPoolAuth, []LDAPConnection{owned})
	pool.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	<-pool.tokens

	request := &bktype.LDAPAuthRequest{
		GUID: "ldapDropSessionGUID", LDAPReplyChan: make(chan *bktype.LDAPReply), HTTPClientContext: t.Context(),
	}

	sendLDAPReplyAndUnlockState(pool, 0, request, &bktype.LDAPReply{})

	line := buf.String()
	if !strings.Contains(line, "reply_channel_blocked_drop") || !strings.Contains(line, `"session":"ldapDropSessionGUID"`) {
		t.Fatalf("dropped reply log = %s, want session ldapDropSessionGUID", line)
	}
}
