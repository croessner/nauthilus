package smtp

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

const mailOperationTimeout = 30 * time.Second

// mailConnection closes blocked protocol operations when their caller cancels.
type mailConnection struct {
	net.Conn
	stop func() bool
}

// Close releases both the connection and its cancellation registration.
func (c *mailConnection) Close() error {
	c.stop()

	return c.Conn.Close()
}

// dialMailConnection bounds dialing, TLS negotiation, and all protocol replies.
func dialMailConnection(ctx context.Context, address string, directTLS bool) (net.Conn, error) {
	dialer := net.Dialer{Timeout: mailOperationTimeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	// One context timer owns expiry, avoiding a socket deadline racing ctx.Err().
	managed := &mailConnection{Conn: conn, stop: context.AfterFunc(ctx, func() { _ = conn.Close() })}
	if !directTLS {
		return managed, nil
	}

	secured := tls.Client(managed, smtpTLSConfig(address, true))
	if err = secured.HandshakeContext(ctx); err != nil {
		_ = secured.Close()

		return nil, err
	}

	return secured, nil
}
