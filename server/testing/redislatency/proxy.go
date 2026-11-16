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

// Package redislatency provides a TCP proxy that adds a fixed one-way delay to Redis traffic in tests.
//
// The proxy models propagation delay: every chunk is forwarded once its arrival time plus the delay has
// passed, so pipelined commands written back to back share the delay instead of paying it once per command.
// It does not model bandwidth, packet loss, or server-side processing time.
package redislatency

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Proxy forwards TCP connections to an upstream address with a fixed one-way delay in both directions.
type Proxy struct {
	listener net.Listener
	upstream string
	delay    time.Duration
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    []net.Conn
	closed   bool
}

// delayedChunk is one read buffer together with the time it may be forwarded.
type delayedChunk struct {
	due  time.Time
	data []byte
}

// Start listens on a loopback port and forwards each accepted connection to upstream.
func Start(upstream string, delay time.Duration) (*Proxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{listener: listener, upstream: upstream, delay: delay}

	proxy.wg.Add(1)

	go proxy.acceptLoop()

	return proxy, nil
}

// Addr returns the loopback address clients should dial.
func (p *Proxy) Addr() string {
	return p.listener.Addr().String()
}

// Close stops accepting connections, closes all forwarded connections, and waits for the workers.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()

	err := p.listener.Close()

	for _, conn := range conns {
		_ = conn.Close()
	}

	p.wg.Wait()

	return err
}

// acceptLoop accepts client connections until the listener is closed.
func (p *Proxy) acceptLoop() {
	defer p.wg.Done()

	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}

		server, err := net.Dial("tcp", p.upstream)
		if err != nil {
			_ = client.Close()

			continue
		}

		if !p.track(client, server) {
			return
		}

		p.wg.Add(2)

		go p.pipe(client, server)
		go p.pipe(server, client)
	}
}

// track records both ends of a forwarded connection so Close can terminate them.
func (p *Proxy) track(conns ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		for _, conn := range conns {
			_ = conn.Close()
		}

		return false
	}

	p.conns = append(p.conns, conns...)

	return true
}

// pipe copies one direction of a connection and delays every chunk by the configured delay.
func (p *Proxy) pipe(src net.Conn, dst net.Conn) {
	defer p.wg.Done()

	chunks := make(chan delayedChunk, 1024)

	go func() {
		defer close(chunks)

		buf := make([]byte, 32*1024)

		for {
			n, err := src.Read(buf)
			if n > 0 {
				// Copy only the bytes read so the proxy does not dominate allocation measurements.
				chunks <- delayedChunk{due: time.Now().Add(p.delay), data: append([]byte(nil), buf[:n]...)}
			}

			if err != nil {
				return
			}
		}
	}()

	for chunk := range chunks {
		if wait := time.Until(chunk.due); wait > 0 {
			time.Sleep(wait)
		}

		if _, err := dst.Write(chunk.data); err != nil {
			if !errors.Is(err, io.EOF) {
				_ = src.Close()
			}

			break
		}
	}

	_ = dst.Close()

	for range chunks {
		// Drain the reader so it can observe the closed connection and exit.
	}
}
