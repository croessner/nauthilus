package pluginruntime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMailFacadeCancelsStalledIO(t *testing.T) {
	for _, lmtp := range []bool{false, true} {
		for _, stall := range []string{"greeting", "deadline", "tls", "MAIL", "DATA", "ack"} {
			t.Run(strconv.FormatBool(lmtp)+"/"+stall, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()

				accepted := make(chan net.Conn, 1)

				go func() {
					conn, acceptErr := listener.Accept()
					if acceptErr == nil {
						stallMailServer(conn, stall)

						accepted <- conn
					}
				}()

				message := newMailTestMessage()
				address := listener.Addr().(*net.TCPAddr)
				message.Server = "127.0.0.1"
				message.Port = address.Port
				message.LMTP = lmtp
				message.TLS = stall == "tls"
				message.StartTLS = false
				message.Username = ""
				message.Password = ""

				ctx, cancel, wantErr := stalledMailContext(stall)
				defer cancel()

				result := make(chan error, 1)
				go func() { result <- NewMailFacade(mailTestScope).Send(ctx, message) }()

				select {
				case conn := <-accepted:
					defer func() { _ = conn.Close() }()
				case <-time.After(time.Second):
					t.Fatal("sender did not reach the stalled operation")
				}

				if stall != "deadline" {
					cancel()
				}

				select {
				case sendErr := <-result:
					if !errors.Is(sendErr, wantErr) {
						t.Fatalf("Send() = %v, want context cancellation", sendErr)
					}
				case <-time.After(time.Second):
					t.Fatal("canceled mail send still waits for the server")
				}
			})
		}
	}
}

// stalledMailContext selects manual cancellation or an independently expiring deadline.
func stalledMailContext(stall string) (context.Context, context.CancelFunc, error) {
	if stall == "deadline" {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)

		return ctx, cancel, context.DeadlineExceeded
	}

	ctx, cancel := context.WithCancel(context.Background())

	return ctx, cancel, context.Canceled
}

// stallMailServer advances a local protocol peer to the requested blocked reply.
func stallMailServer(conn net.Conn, stall string) {
	if stall == "greeting" || stall == "tls" || stall == "deadline" {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprint(conn, "220 test.example ESMTP\r\n")
	reader := bufio.NewReader(conn)
	inData := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		if inData {
			if line == ".\r\n" {
				return
			}

			continue
		}

		if strings.HasPrefix(line, stall) {
			return
		}

		if strings.HasPrefix(line, "DATA") {
			_, _ = fmt.Fprint(conn, "354 send data\r\n")
			inData = true
		} else {
			_, _ = fmt.Fprint(conn, "250 OK\r\n")
		}
	}
}
