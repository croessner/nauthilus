package smtp

import (
	"errors"
	"io"
	"testing"
)

func TestSendEmailContentAcknowledgement(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "accepted"}[accepted], func(t *testing.T) {
			client := &acknowledgementClient{accepted: accepted}

			err := sendEmailContent(client, "sender@example.test", []string{"recipient@example.test"}, []byte("test"))
			if (err == nil) != accepted {
				t.Fatalf("send error = %v, accepted = %t", err, accepted)
			}
		})
	}
}

// acknowledgementClient isolates the DATA acceptance boundary from QUIT failure.
type acknowledgementClient struct {
	GenericClient
	accepted bool
}

// Mail accepts the test envelope sender.
func (*acknowledgementClient) Mail(string) error { return nil }

// Rcpt accepts the test recipient.
func (*acknowledgementClient) Rcpt(string) error { return nil }

// Data returns a writer whose close acknowledges or rejects the message.
func (c *acknowledgementClient) Data() (io.WriteCloser, error) { return c, nil }

// Write accepts the test message bytes.
func (*acknowledgementClient) Write(p []byte) (int, error) { return len(p), nil }

// Close models the final DATA reply.
func (c *acknowledgementClient) Close() error {
	if !c.accepted {
		return errors.New("message rejected")
	}

	return nil
}

// Quit fails after the server has already reported the delivery outcome.
func (*acknowledgementClient) Quit() error { return errors.New("connection closed") }
