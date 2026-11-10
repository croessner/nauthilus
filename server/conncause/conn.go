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

package conncause

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// causeListener wraps every accepted connection in a causeConn.
type causeListener struct {
	net.Listener
}

// NewListener wraps inner so that accepted connections report their failure cause. Place it
// below TLS (http.Server.ServeTLS adds TLS on top) and above any PROXY protocol listener.
// The server must also set ConnContext for the cause to reach request contexts.
func NewListener(inner net.Listener) net.Listener {
	return &causeListener{Listener: inner}
}

// Accept wraps the next accepted connection.
func (l *causeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &causeConn{Conn: conn}, nil
}

// ConnContext is an http.Server.ConnContext hook that derives a cancel-cause context for each
// connection accepted by a NewListener listener. Other connections keep the given context.
func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	wrapped, ok := unwrapConn(conn)
	if !ok {
		return ctx
	}

	connCtx, cancel := context.WithCancelCause(ctx)
	wrapped.cancel = cancel

	return connCtx
}

// unwrapConn returns the causeConn below an optional TLS layer.
func unwrapConn(conn net.Conn) (*causeConn, bool) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}

	wrapped, ok := conn.(*causeConn)

	return wrapped, ok
}

// closeWriter is implemented by connections that support a TCP half-close.
type closeWriter interface {
	CloseWrite() error
}

// causeConn cancels its connection context with a classified cause on the first transport error.
//
// The cancel function is set by ConnContext on the accepting goroutine before net/http starts the
// connection goroutine, so it needs no synchronization. Read and write deadlines in the past are
// net/http's way to abort a pending background read; the resulting timeouts are expected and must
// not end the connection context, otherwise every following keep-alive request would start canceled.
type causeConn struct {
	net.Conn

	cancel context.CancelCauseFunc

	readAborted  atomic.Bool
	writeAborted atomic.Bool
}

// Read forwards to the wrapped connection and records a failure cause.
func (c *causeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.fail(err, &c.readAborted)
	}

	return n, err
}

// Write forwards to the wrapped connection and records a failure cause.
func (c *causeConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.fail(err, &c.writeAborted)
	}

	return n, err
}

// ReadFrom keeps the sendfile/splice fast path of the wrapped connection. Like net/http, which
// bypasses its own error tracking here, it does not record a cause because the error may come
// from the source reader.
func (c *causeConn) ReadFrom(src io.Reader) (int64, error) {
	if readerFrom, ok := c.Conn.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(src)
	}

	return io.Copy(writerOnly{Writer: c}, src)
}

// CloseWrite half-closes the wrapped connection when it supports it.
func (c *causeConn) CloseWrite() error {
	if writer, ok := c.Conn.(closeWriter); ok {
		return writer.CloseWrite()
	}

	return nil
}

// Close marks the connection as closed locally before closing it. A cause recorded earlier wins.
func (c *causeConn) Close() error {
	c.cancelWith(ErrConnectionClosedLocally)

	return c.Conn.Close()
}

// SetDeadline forwards to the wrapped connection and tracks deadline aborts.
func (c *causeConn) SetDeadline(t time.Time) error {
	aborted := isAbortDeadline(t)

	c.readAborted.Store(aborted)
	c.writeAborted.Store(aborted)

	return c.Conn.SetDeadline(t)
}

// SetReadDeadline forwards to the wrapped connection and tracks read aborts.
func (c *causeConn) SetReadDeadline(t time.Time) error {
	c.readAborted.Store(isAbortDeadline(t))

	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline forwards to the wrapped connection and tracks write aborts.
func (c *causeConn) SetWriteDeadline(t time.Time) error {
	c.writeAborted.Store(isAbortDeadline(t))

	return c.Conn.SetWriteDeadline(t)
}

// fail records the cause for err unless it is the expected timeout of a deliberate abort.
func (c *causeConn) fail(err error, aborted *atomic.Bool) {
	if aborted.Load() && isTimeout(err) {
		return
	}

	c.cancelWith(classify(err))
}

// cancelWith cancels the connection context; only the first cause is kept.
func (c *causeConn) cancelWith(cause error) {
	if c.cancel != nil {
		c.cancel(cause)
	}
}

// isAbortDeadline reports whether t is a deadline in the past, which interrupts pending I/O.
func isAbortDeadline(t time.Time) bool {
	return !t.IsZero() && !t.After(time.Now())
}

// writerOnly hides io.ReaderFrom so io.Copy does not recurse into causeConn.ReadFrom.
type writerOnly struct {
	io.Writer
}
