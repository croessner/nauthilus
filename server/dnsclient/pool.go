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
	"sync/atomic"
	"time"
)

// pooledSocket is a connected UDP socket together with its usage count.
type pooledSocket struct {
	conn *net.UDPConn
	uses int
}

// socketPool keeps idle UDP sockets per resolver address. A socket serves one
// query at a time, so responses never need to be routed between callers.
type socketPool struct {
	dialer   *net.Dialer
	observer Observer
	idle     map[string]chan *pooledSocket
	size     int
	maxUses  int
	mu       sync.Mutex
	closed   bool
}

// newSocketPool creates a pool that keeps up to size idle sockets per resolver.
func newSocketPool(dialer *net.Dialer, observer Observer, size, maxUses int) *socketPool {
	return &socketPool{
		dialer:   dialer,
		observer: observer,
		idle:     make(map[string]chan *pooledSocket),
		size:     size,
		maxUses:  maxUses,
	}
}

// lease returns an idle socket for the address or dials a new one. It never
// blocks on the pool: when no idle socket is available the query gets its own.
func (p *socketPool) lease(ctx context.Context, network, address string) (net.Conn, error) {
	idle := p.idleSockets(network, address)

	select {
	case socket := <-idle:
		p.observer.SocketLeased(true)

		return &leasedConn{UDPConn: socket.conn, socket: socket, pool: p, idle: idle}, nil
	default:
	}

	conn, err := p.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return conn, nil
	}

	p.observer.SocketLeased(false)

	return &leasedConn{UDPConn: udpConn, socket: &pooledSocket{conn: udpConn}, pool: p, idle: idle}, nil
}

// idleSockets returns the idle queue for one resolver address, creating it on first use.
func (p *socketPool) idleSockets(network, address string) chan *pooledSocket {
	key := network + " " + address

	p.mu.Lock()
	defer p.mu.Unlock()

	idle, ok := p.idle[key]
	if !ok {
		idle = make(chan *pooledSocket, p.size)
		p.idle[key] = idle
	}

	return idle
}

// release returns a socket to its idle queue, or closes it when it is no
// longer safe or worthwhile to reuse.
func (p *socketPool) release(socket *pooledSocket, idle chan *pooledSocket, reusable bool) error {
	socket.uses++

	if !reusable || socket.uses >= p.maxUses || socket.conn.SetDeadline(time.Time{}) != nil {
		return socket.conn.Close()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return socket.conn.Close()
	}

	select {
	case idle <- socket:
		return nil
	default:
		return socket.conn.Close()
	}
}

// close drains and closes all idle sockets and rejects later releases.
func (p *socketPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true

	for _, idle := range p.idle {
		drainSockets(idle)
	}
}

// drainSockets closes every socket currently waiting in the idle queue.
func drainSockets(idle chan *pooledSocket) {
	for {
		select {
		case socket := <-idle:
			_ = socket.conn.Close()
		default:
			return
		}
	}
}

// leasedConn is the view of a pooled socket handed to the resolver for one
// query. Closing it returns the socket to the pool instead of closing it.
type leasedConn struct {
	*net.UDPConn

	socket *pooledSocket
	pool   *socketPool
	idle   chan *pooledSocket
	once   sync.Once

	// sent and answered track whether the query got its response. A socket whose
	// query stayed unanswered is retired, so a late response can never reach the
	// next query on the same socket.
	sent     atomic.Bool
	answered atomic.Bool
	broken   atomic.Bool
}

// Read reads a response datagram and records whether the socket stays healthy.
func (l *leasedConn) Read(b []byte) (int, error) {
	n, err := l.UDPConn.Read(b)
	if err == nil {
		l.answered.Store(true)
	}

	l.noteError(err)

	return n, err
}

// Write sends the query datagram and records whether the socket stays healthy.
func (l *leasedConn) Write(b []byte) (int, error) {
	n, err := l.UDPConn.Write(b)
	if err == nil {
		l.sent.Store(true)
	}

	l.noteError(err)

	return n, err
}

// Close hands the socket back to the pool exactly once.
func (l *leasedConn) Close() error {
	var err error

	l.once.Do(func() {
		reusable := !l.broken.Load() && l.sent.Load() == l.answered.Load()
		err = l.pool.release(l.socket, l.idle, reusable)
	})

	return err
}

// noteError marks the socket as broken for every failure except a deadline.
func (l *leasedConn) noteError(err error) {
	if err == nil {
		return
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return
	}

	l.broken.Store(true)
}
