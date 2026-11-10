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

// Package conncause attaches the transport-level reason for a dead HTTP connection to the
// request context as a context cause.
//
// net/http and x/net/http2 cancel request contexts with context.WithCancel and discard the
// connection error, so context.Cause only ever reports context.Canceled. This package wraps
// accepted connections and installs a cancel-cause context per connection through
// http.Server.ConnContext. The wrapper records the classified error before net/http sees it,
// so the request context inherits the real cause.
package conncause

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

var (
	// ErrClientDisconnected means the peer closed or reset the connection.
	ErrClientDisconnected = errors.New("client disconnected")

	// ErrConnectionTimeout means a server-side read or write deadline expired.
	ErrConnectionTimeout = errors.New("connection deadline exceeded")

	// ErrConnectionClosedLocally means the server closed the connection itself.
	ErrConnectionClosedLocally = errors.New("connection closed locally")

	// ErrConnectionFailed means the connection failed for a reason that is not classified further.
	ErrConnectionFailed = errors.New("connection failed")
)

// clientDisconnectErrors lists transport errors that mean the peer went away.
var clientDisconnectErrors = []error{
	io.EOF,
	io.ErrUnexpectedEOF,
	syscall.ECONNRESET,
	syscall.EPIPE,
	syscall.ECONNABORTED,
}

// Termination describes why a request context was canceled.
type Termination struct {
	// Cause is the context cause; it wraps one of the package sentinels when the transport reported it.
	Cause error

	// ClientInitiated reports whether the client ended the request.
	ClientInitiated bool
}

// RequestTermination inspects the context of an *http.Request* and reports whether it was canceled
// and why. It returns false when the context is still active or ended by a deadline.
//
// A plain context.Canceled without an explicit cause counts as client-initiated: only net/http
// cancels the request context itself, and it does so without a cause for HTTP/2 stream resets and
// TLS close_notify, which both come from the client. Pass the request context, not a derived one,
// because derived contexts may be canceled by internal code.
func RequestTermination(ctx context.Context) (Termination, bool) {
	if !errors.Is(ctx.Err(), context.Canceled) {
		return Termination{}, false
	}

	cause := context.Cause(ctx)

	return Termination{
		Cause:           cause,
		ClientInitiated: errors.Is(cause, context.Canceled) || errors.Is(cause, ErrClientDisconnected),
	}, true
}

// classify maps a transport error to a cause that wraps both a package sentinel and the original error.
func classify(err error) error {
	return fmt.Errorf("%w: %w", sentinelFor(err), err)
}

// sentinelFor selects the package sentinel describing a transport error.
func sentinelFor(err error) error {
	switch {
	case isClientDisconnect(err):
		return ErrClientDisconnected
	case errors.Is(err, net.ErrClosed):
		return ErrConnectionClosedLocally
	case isTimeout(err):
		return ErrConnectionTimeout
	default:
		return ErrConnectionFailed
	}
}

// isClientDisconnect reports whether err means the peer closed or reset the connection.
func isClientDisconnect(err error) bool {
	for _, disconnect := range clientDisconnectErrors {
		if errors.Is(err, disconnect) {
			return true
		}
	}

	return false
}

// isTimeout reports whether err is an expired deadline.
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	netErr, ok := errors.AsType[net.Error](err)

	return ok && netErr.Timeout()
}
