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
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testRequestTimeout = 5 * time.Second
	testRequestLine    = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
)

// causeRecorder captures the request context cause observed by a test handler.
type causeRecorder struct {
	started chan struct{}
	causes  chan error
}

// newCauseRecorder creates a recorder with buffered channels for one request.
func newCauseRecorder() *causeRecorder {
	return &causeRecorder{started: make(chan struct{}, 1), causes: make(chan error, 1)}
}

// waitForCancel is a handler that blocks until the request context ends and records its cause.
func (r *causeRecorder) waitForCancel(_ http.ResponseWriter, req *http.Request) {
	r.started <- struct{}{}

	select {
	case <-req.Context().Done():
		r.causes <- context.Cause(req.Context())
	case <-time.After(testRequestTimeout):
		r.causes <- errors.New("request context was never canceled")
	}
}

// await returns the recorded cause or fails the test after the timeout.
func (r *causeRecorder) await(t *testing.T) error {
	t.Helper()

	select {
	case cause := <-r.causes:
		return cause
	case <-time.After(2 * testRequestTimeout):
		t.Fatal("handler did not report a cause")

		return nil
	}
}

// awaitStart blocks until the handler is running.
func (r *causeRecorder) awaitStart(t *testing.T) {
	t.Helper()

	select {
	case <-r.started:
	case <-time.After(testRequestTimeout):
		t.Fatal("handler did not start")
	}
}

// newCauseServer starts an unstarted httptest server with the cause listener and ConnContext installed.
func newCauseServer(t *testing.T, handler http.Handler, useTLS bool) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.Listener = NewListener(server.Listener)
	server.Config.ConnContext = ConnContext

	if useTLS {
		server.StartTLS()
	} else {
		server.Start()
	}

	t.Cleanup(server.Close)

	return server
}

// mustNoError stops the test when err is non-nil.
func mustNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// TestClientDisconnectBecomesRequestCause pins that closing the client TCP connection mid-request
// surfaces ErrClientDisconnected as the request context cause, for plain HTTP and TLS.
func TestClientDisconnectBecomesRequestCause(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", useTLS), func(t *testing.T) {
			recorder := newCauseRecorder()
			server := newCauseServer(t, http.HandlerFunc(recorder.waitForCancel), useTLS)
			rawConn := dialRaw(t, server, useTLS)

			recorder.awaitStart(t)
			mustNoError(t, rawConn.Close())

			cause := recorder.await(t)
			assert.ErrorIs(t, cause, ErrClientDisconnected)

			termination, ended := RequestTermination(contextCanceledWith(cause))
			assert.True(t, ended)
			assert.True(t, termination.ClientInitiated)
		})
	}
}

// dialRaw opens a connection to the server, sends one request, and returns the raw TCP connection
// so the test can drop it without a TLS close_notify.
func dialRaw(t *testing.T, server *httptest.Server, useTLS bool) net.Conn {
	t.Helper()

	address := server.Listener.Addr().String()
	rawConn, err := net.DialTimeout("tcp", address, testRequestTimeout)
	mustNoError(t, err)

	var writer io.Writer = rawConn

	if useTLS {
		transport, ok := server.Client().Transport.(*http.Transport)
		if !ok {
			t.Fatalf("unexpected test transport %T", server.Client().Transport)
		}

		tlsConfig := transport.TLSClientConfig.Clone()
		tlsConfig.ServerName = "127.0.0.1"

		tlsConn := tls.Client(rawConn, tlsConfig)
		mustNoError(t, tlsConn.Handshake())

		writer = tlsConn
	}

	_, err = io.WriteString(writer, testRequestLine)
	mustNoError(t, err)

	return rawConn
}

// TestKeepAliveRequestsAreNotCanceledByPendingReadAbort pins that net/http's abortPendingRead after
// a finished request does not cancel the connection context of the next keep-alive request.
func TestKeepAliveRequestsAreNotCanceledByPendingReadAbort(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
			http.Error(w, context.Cause(req.Context()).Error(), http.StatusInternalServerError)
		case <-time.After(50 * time.Millisecond):
			w.WriteHeader(http.StatusNoContent)
		}
	})

	server := newCauseServer(t, handler, false)
	rawConn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), testRequestTimeout)
	mustNoError(t, err)

	t.Cleanup(func() { _ = rawConn.Close() })

	reader := bufio.NewReader(rawConn)

	for attempt := range 3 {
		_, err = io.WriteString(rawConn, testRequestLine)
		mustNoError(t, err)

		response, readErr := http.ReadResponse(reader, nil)
		mustNoError(t, readErr)

		_ = response.Body.Close()

		assert.Equal(t, http.StatusNoContent, response.StatusCode, "request %d", attempt)
	}
}

// TestWriteTimeoutIsNotClientInitiated pins that a server WriteTimeout surfaces ErrConnectionTimeout
// and is not classified as a client disconnect.
func TestWriteTimeoutIsNotClientInitiated(t *testing.T) {
	causes := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(200 * time.Millisecond)

		_, _ = io.WriteString(w, "late")
		http.NewResponseController(w).Flush() //nolint:errcheck // The flush is expected to fail.

		causes <- context.Cause(req.Context())
	})

	server := httptest.NewUnstartedServer(handler)
	server.Listener = NewListener(server.Listener)
	server.Config.ConnContext = ConnContext
	server.Config.WriteTimeout = 50 * time.Millisecond
	server.Start()

	t.Cleanup(server.Close)

	response, err := server.Client().Get(server.URL)
	if err == nil {
		_ = response.Body.Close()
	}

	var cause error

	select {
	case cause = <-causes:
	case <-time.After(testRequestTimeout):
		t.Fatal("handler did not report a cause")
	}

	assert.ErrorIs(t, cause, ErrConnectionTimeout)

	termination, ended := RequestTermination(contextCanceledWith(cause))
	assert.True(t, ended)
	assert.False(t, termination.ClientInitiated)
}

// contextCanceledWith returns a context canceled with the given cause.
func contextCanceledWith(cause error) context.Context {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)

	return ctx
}

// TestRequestTermination pins the classification of request context endings.
func TestRequestTermination(t *testing.T) {
	plainCanceled, cancel := context.WithCancel(context.Background())
	cancel()

	deadline, deadlineCancel := context.WithTimeout(context.Background(), -time.Second)
	defer deadlineCancel()

	tests := []struct {
		ctx             context.Context
		name            string
		wantEnded       bool
		wantClientEnded bool
	}{
		{name: "active", ctx: context.Background()},
		{name: "deadline exceeded", ctx: deadline},
		{name: "plain cancel", ctx: plainCanceled, wantEnded: true, wantClientEnded: true},
		{name: "client disconnected", ctx: contextCanceledWith(classify(io.EOF)), wantEnded: true, wantClientEnded: true},
		{name: "connection reset", ctx: contextCanceledWith(classify(syscall.ECONNRESET)), wantEnded: true, wantClientEnded: true},
		{name: "timeout", ctx: contextCanceledWith(classify(osDeadlineError())), wantEnded: true},
		{name: "closed locally", ctx: contextCanceledWith(ErrConnectionClosedLocally), wantEnded: true},
		{name: "unknown failure", ctx: contextCanceledWith(classify(errors.New("boom"))), wantEnded: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			termination, ended := RequestTermination(test.ctx)

			assert.Equal(t, test.wantEnded, ended)
			assert.Equal(t, test.wantClientEnded, termination.ClientInitiated)
		})
	}
}

// osDeadlineError returns a real network timeout error from an expired read deadline.
func osDeadlineError() error {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	_ = client.SetReadDeadline(time.Now().Add(-time.Second))

	_, err := client.Read(make([]byte, 1))

	return err
}

// TestClassifyWrapsOriginalError pins that the classified cause keeps the transport error inspectable.
func TestClassifyWrapsOriginalError(t *testing.T) {
	cause := classify(syscall.EPIPE)

	assert.ErrorIs(t, cause, ErrClientDisconnected)
	assert.ErrorIs(t, cause, syscall.EPIPE)
	assert.ErrorIs(t, classify(net.ErrClosed), ErrConnectionClosedLocally)
	assert.ErrorIs(t, classify(errors.New("boom")), ErrConnectionFailed)
}
