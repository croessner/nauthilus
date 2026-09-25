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
	stderrors "errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/errors"
)

// withLDAPConnectTimeout shortens the connect deadline for one test.
func withLDAPConnectTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()

	previous := ldapConnectTimeout
	ldapConnectTimeout = timeout

	t.Cleanup(func() { ldapConnectTimeout = previous })
}

// refusedLDAPTarget returns a local ldap:// URI on a port that refuses connections.
func refusedLDAPTarget(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	target := "ldap://" + listener.Addr().String()
	_ = listener.Close()

	return target
}

func TestConnectStopsBackoffAtTheConnectDeadline(t *testing.T) {
	withLDAPConnectTimeout(t, 300*time.Millisecond)

	conf := &config.LDAPConf{
		ServerURIs:      []string{refusedLDAPTarget(t)},
		PoolName:        "connect-deadline-backoff",
		RetryMax:        5,
		RetryBase:       2 * time.Second,
		RetryMaxBackoff: 5 * time.Second,
	}

	start := time.Now()
	err := (&LDAPConnectionImpl{}).Connect("guid", &config.FileSettings{Server: &config.ServerSection{}}, slog.Default(), conf)
	elapsed := time.Since(start)

	if !stderrors.Is(err, errors.ErrLDAPConnectTimeout) {
		t.Fatalf("Connect() error = %v, want ErrLDAPConnectTimeout", err)
	}

	if elapsed > time.Second {
		t.Fatalf("Connect() returned after %s; the backoff must end at the connect deadline", elapsed)
	}
}

func TestConnectEstablishesAConnectionWithinTheDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	defer listener.Close()

	accepted := make(chan net.Conn, 1)

	go func() {
		if connection, acceptErr := listener.Accept(); acceptErr == nil {
			accepted <- connection
		}
	}()

	conf := &config.LDAPConf{ServerURIs: []string{"ldap://" + listener.Addr().String()}, PoolName: "connect-deadline-success"}
	connection := &LDAPConnectionImpl{}

	if err := connection.Connect("guid", &config.FileSettings{Server: &config.ServerSection{}}, slog.Default(), conf); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if connection.GetConn() == nil {
		t.Fatal("Connect() did not keep the established connection")
	}

	_ = connection.GetConn().Close()

	select {
	case server := <-accepted:
		_ = server.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the connection")
	}
}
