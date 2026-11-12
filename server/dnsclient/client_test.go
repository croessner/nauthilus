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

package dnsclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

const (
	testLookupName   = "2.0.0.127.rbl.example."
	testLookupBudget = 600 * time.Millisecond
	testRetryGap     = 50 * time.Millisecond

	dnsHeaderLength    = 12
	dnsQuestionTrailer = 4
	dnsRCodeNameError  = 3
)

// fakeReply describes how the fake resolver treats one incoming query.
type fakeReply struct {
	delay    time.Duration
	drop     bool
	notFound bool
}

// fakeResolver is a loopback UDP DNS server with scripted packet loss and delays.
type fakeResolver struct {
	conn    *net.UDPConn
	script  func(query int) fakeReply
	ports   map[int]struct{}
	queries int
	mu      sync.Mutex
}

// newFakeResolver starts a fake resolver that answers every query according to script.
func newFakeResolver(t *testing.T, script func(query int) fakeReply) *fakeResolver {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &fakeResolver{conn: conn, script: script, ports: make(map[int]struct{})}

	t.Cleanup(func() { _ = conn.Close() })

	go server.serve()

	return server
}

// address returns the listening address in host:port form.
func (s *fakeResolver) address() string {
	return s.conn.LocalAddr().String()
}

// serve reads queries until the socket is closed.
func (s *fakeResolver) serve() {
	buffer := make([]byte, 1500)

	for {
		n, peer, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		query := append([]byte(nil), buffer[:n]...)
		reply := s.record(peer)

		if reply.drop {
			continue
		}

		go s.answer(query, peer, reply)
	}
}

// record counts the query, remembers its source port, and returns the scripted reply.
func (s *fakeResolver) record(peer *net.UDPAddr) fakeReply {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.queries++
	s.ports[peer.Port] = struct{}{}

	return s.script(s.queries)
}

// answer sends the scripted response after the scripted delay.
func (s *fakeResolver) answer(query []byte, peer *net.UDPAddr, reply fakeReply) {
	time.Sleep(reply.delay)

	if response := buildResponse(query, reply.notFound); response != nil {
		_, _ = s.conn.WriteToUDP(response, peer)
	}
}

// stats returns the number of received queries and distinct client source ports.
func (s *fakeResolver) stats() (queries int, ports int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.queries, len(s.ports)
}

// buildResponse turns a query into an A record answer for 127.0.0.2 or a name error.
func buildResponse(query []byte, notFound bool) []byte {
	end := dnsHeaderLength

	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}

	end += 1 + dnsQuestionTrailer
	if end > len(query) {
		return nil
	}

	response := append([]byte(nil), query[:end]...)
	response[2], response[3] = 0x81, 0x80
	// Drop the authority and additional sections of the query (EDNS0 OPT record).
	copy(response[6:dnsHeaderLength], []byte{0, 0, 0, 0, 0, 0})

	if notFound {
		response[3] |= dnsRCodeNameError

		return response
	}

	response[7] = 1

	return append(response, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 2)
}

// recordingObserver captures observer callbacks for assertions.
type recordingObserver struct {
	results  []string
	attempts []int
	reused   int
	created  int
	mu       sync.Mutex
}

func (o *recordingObserver) LookupDone(result string, attempts int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.results = append(o.results, result)
	o.attempts = append(o.attempts, attempts)
}

func (o *recordingObserver) SocketLeased(reused bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if reused {
		o.reused++
	} else {
		o.created++
	}
}

// newTestClient builds a client against the fake resolver and closes it with the test.
func newTestClient(t *testing.T, settings Settings, observer Observer) *Client {
	t.Helper()

	client := New(settings, observer)

	t.Cleanup(client.Close)

	return client
}

// dropFirst drops the first query and answers all later ones.
func dropFirst(query int) fakeReply {
	return fakeReply{drop: query == 1}
}

func TestLookupWithDroppedFirstDatagram(t *testing.T) {
	tests := []struct {
		name        string
		attempts    int
		wantTimeout bool
		wantQueries int
	}{
		{name: "single attempt times out", attempts: 1, wantTimeout: true, wantQueries: 1},
		{name: "overlapping retry recovers", attempts: 3, wantQueries: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFakeResolver(t, dropFirst)
			observer := &recordingObserver{}
			client := newTestClient(t, Settings{
				Resolver:      server.address(),
				Timeout:       testLookupBudget,
				RetryInterval: testRetryGap,
				Attempts:      tt.attempts,
			}, observer)

			started := time.Now()
			ips, err := client.LookupIP(context.Background(), "ip4", testLookupName)
			elapsed := time.Since(started)

			if tt.wantTimeout {
				assertTimeout(t, err, elapsed)
			} else {
				assertListed(t, ips, err)

				if elapsed >= testLookupBudget {
					t.Fatalf("lookup took %v, want less than the %v budget", elapsed, testLookupBudget)
				}
			}

			if queries, _ := server.stats(); queries != tt.wantQueries {
				t.Fatalf("server saw %d queries, want %d", queries, tt.wantQueries)
			}
		})
	}
}

func TestLookupKeepsWaitingForSlowFirstAnswer(t *testing.T) {
	// Every answer takes longer than the retry gap, so only an attempt that is
	// allowed to keep running past later attempts can finish inside the budget.
	server := newFakeResolver(t, func(int) fakeReply {
		return fakeReply{delay: 3 * testRetryGap}
	})
	observer := &recordingObserver{}
	client := newTestClient(t, Settings{
		Resolver:      server.address(),
		Timeout:       testLookupBudget,
		RetryInterval: testRetryGap,
		Attempts:      2,
	}, observer)

	ips, err := client.LookupIP(context.Background(), "ip4", testLookupName)

	assertListed(t, ips, err)
}

func TestLookupNotFoundIsNotRetried(t *testing.T) {
	server := newFakeResolver(t, func(int) fakeReply {
		return fakeReply{notFound: true}
	})
	observer := &recordingObserver{}
	client := newTestClient(t, Settings{
		Resolver:      server.address(),
		Timeout:       testLookupBudget,
		RetryInterval: testRetryGap,
		Attempts:      3,
	}, observer)

	_, err := client.LookupIP(context.Background(), "ip4", testLookupName)

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("got error %v, want a not-found DNS error", err)
	}

	if queries, _ := server.stats(); queries != 1 {
		t.Fatalf("server saw %d queries, want 1", queries)
	}

	if len(observer.results) != 1 || observer.results[0] != ResultNotFound || observer.attempts[0] != 1 {
		t.Fatalf("observer saw results %v with attempts %v", observer.results, observer.attempts)
	}
}

func TestLookupHonorsCallerCancellation(t *testing.T) {
	server := newFakeResolver(t, func(int) fakeReply {
		return fakeReply{drop: true}
	})
	client := newTestClient(t, Settings{
		Resolver:      server.address(),
		Timeout:       testLookupBudget,
		RetryInterval: testRetryGap,
		Attempts:      3,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())

	time.AfterFunc(testRetryGap, cancel)

	_, err := client.LookupIP(ctx, "ip4", testLookupName)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got error %v, want context cancellation", err)
	}
}

// assertListed verifies the scripted A record answer.
func assertListed(t *testing.T, ips []net.IP, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}

	if len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("got answers %v, want 127.0.0.2", ips)
	}
}

// assertTimeout verifies that the lookup ran into its budget.
func assertTimeout(t *testing.T, err error, elapsed time.Duration) {
	t.Helper()

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsTimeout {
		t.Fatalf("got error %v, want a DNS timeout", err)
	}

	if elapsed < testLookupBudget {
		t.Fatalf("lookup returned after %v, want at least the %v budget", elapsed, testLookupBudget)
	}
}
