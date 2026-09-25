// Copyright (C) 2026 Christian Rößner
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
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/go-ldap/ldap/v3"
)

// acceptingLDAPTarget returns an ldap:// URI whose listener accepts every connection, so a reconnect succeeds.
func acceptingLDAPTarget(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			t.Cleanup(func() { _ = connection.Close() })
		}
	}()

	return "ldap://" + listener.Addr().String()
}

func TestTransportErrorKeepsTheBorrowedSlotWithItsOwner(t *testing.T) {
	setupLDAPPoolTestConfig()
	config.SetTestEnvironmentConfig(&config.EnvironmentSettings{})

	client, server := net.Pipe()

	t.Cleanup(func() { _ = server.Close() })

	conn := ldap.NewConn(client, false)
	conn.Start()

	owned := &LDAPConnectionImpl{}
	owned.SetConn(conn)
	owned.SetState(definitions.LDAPStateBusy) // borrowed by request A

	pool := newLookupTestPool(t.Context(), definitions.LDAPPoolAuth, []LDAPConnection{owned})
	pool.conf = []*config.LDAPConf{{ServerURIs: []string{acceptingLDAPTarget(t)}, PoolName: "slot-ownership"}}
	pool.logger = slog.Default()
	<-pool.tokens // request A holds the capacity token

	// Request A's operation fails on the transport.
	owned.closeOnTransportError(ldap.NewError(ldap.ErrorNetwork, net.ErrClosed))

	// Request B scans the pool while A still owns the slot; it must not reconnect and take it.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	if index := pool.processConnection(ctx, 0, "request-b"); index != definitions.LDAPPoolExhausted {
		t.Fatalf("request B took slot %d while request A still owned it", index)
	}

	if owned.GetState() != definitions.LDAPStateBusy {
		t.Fatalf("slot state = %v while request A owns it, want busy", owned.GetState())
	}

	// Request A releases the slot; the broken connection must come back as closed, not free.
	request := &bktype.LDAPAuthRequest{LDAPReplyChan: make(chan *bktype.LDAPReply, 1), HTTPClientContext: t.Context()}
	sendLDAPReplyAndUnlockState(pool, 0, request, &bktype.LDAPReply{})

	if owned.GetState() != definitions.LDAPStateClosed {
		t.Fatalf("slot state after release = %v, want closed so the next borrower reconnects", owned.GetState())
	}

	if len(pool.tokens) != 1 {
		t.Fatal("the release did not return the capacity token")
	}
}
