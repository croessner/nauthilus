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

//nolint:goconst,gocyclo,funlen,wsl_v5 // Scripted protocol conversations are clearer with inline literals.
package monitoring

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/pires/go-proxyproto"
)

func TestAuthSelectorAutoPlainInitialResponse(t *testing.T) {
	t.Parallel()

	selector := NewAuthSelector(slog.Default(), authSelectorServer("imap", config.BackendAuthMechanismAuto), BackendCheckPhaseDeep)
	capabilities := NewAuthCapabilities("imap capability")
	capabilities.AddMechanism(HealthAuthMechanismPlain, true, false)
	capabilities.AddMechanism(HealthAuthMechanismLogin, true, false)
	capabilities.SASLIR = true

	selection, err := selector.Select(capabilities)
	if err != nil {
		t.Fatalf("select auth mechanism failed: %v", err)
	}

	if selection.Mechanism != HealthAuthMechanismPlain {
		t.Fatalf("expected PLAIN, got %q", selection.Mechanism)
	}

	if !selection.InitialResponse {
		t.Fatal("expected selector to use initial response")
	}
}

func TestAuthSelectorClassicWhenInitialResponseUnavailable(t *testing.T) {
	t.Parallel()

	selector := NewAuthSelector(slog.Default(), authSelectorServer("imap", config.BackendAuthMechanismLogin), BackendCheckPhaseDeep)
	capabilities := NewAuthCapabilities("imap capability")
	capabilities.AddMechanism(HealthAuthMechanismLogin, false, false)

	selection, err := selector.Select(capabilities)
	if err != nil {
		t.Fatalf("select auth mechanism failed: %v", err)
	}

	if selection.Mechanism != HealthAuthMechanismLogin {
		t.Fatalf("expected LOGIN, got %q", selection.Mechanism)
	}

	if selection.InitialResponse {
		t.Fatal("expected classic exchange without SASL-IR")
	}
}

func TestAuthSelectorExplicitMechanismUnavailableLogsError(t *testing.T) {
	t.Parallel()

	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server := authSelectorServer("imap", config.BackendAuthMechanismLogin)
	selector := NewAuthSelector(logger, server, BackendCheckPhaseDeep)
	capabilities := NewAuthCapabilities("imap capability")
	capabilities.AddMechanism(HealthAuthMechanismPlain, true, false)
	capabilities.SASLIR = true

	_, err := selector.Select(capabilities)
	if err == nil {
		t.Fatal("expected missing explicit mechanism to fail")
	}

	var unavailable *AuthMechanismUnavailableError
	if !stderrors.As(err, &unavailable) {
		t.Fatalf("expected AuthMechanismUnavailableError, got %T: %v", err, err)
	}

	logText := logBuffer.String()
	for _, want := range []string{
		"Backend health-check auth mechanism unavailable",
		"configured_auth_mechanism",
		"LOGIN",
		"advertised_auth_mechanisms",
		"sasl_ir",
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("expected log to contain %q, got %s", want, logText)
		}
	}
}

func TestParseSMTPAuthCapabilitiesNormalizesAuthForms(t *testing.T) {
	t.Parallel()

	capabilities := ParseSMTPAuthCapabilities([]string{
		"250-localhost",
		"250-AUTH PLAIN LOGIN",
		"250 AUTH=PLAIN",
	})

	if !capabilities.HasMechanism(HealthAuthMechanismPlain) {
		t.Fatal("expected AUTH=PLAIN to normalize to PLAIN")
	}

	if !capabilities.HasMechanism(HealthAuthMechanismLogin) {
		t.Fatal("expected AUTH PLAIN LOGIN to expose LOGIN")
	}
}

func TestSMTPFallsBackOnceFromInitialResponseSyntaxRejection(t *testing.T) {
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server := &config.BackendServer{
		Protocol:      "smtp",
		Host:          "127.0.0.1",
		Port:          465,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismPlain,
	}
	plainPayload := base64.StdEncoding.EncodeToString([]byte("\x00monitor\x00secret"))
	clientConn, waitServer := newTLSScriptConn(t, func(conn net.Conn) error {
		reader := bufio.NewReader(conn)
		if err := writeTestLine(conn, "220 smtp.example.test ESMTP"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || !strings.HasPrefix(got, "EHLO ") {
			return fmt.Errorf("EHLO command = %q, err = %w", got, err)
		}

		if err := writeTestLines(conn, "250-smtp.example.test", "250-AUTH PLAIN LOGIN", "250 OK"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "AUTH PLAIN "+plainPayload {
			return fmt.Errorf("initial AUTH command = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "501 5.5.4 invalid command syntax"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "AUTH PLAIN" {
			return fmt.Errorf("classic AUTH command = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "334 "); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != plainPayload {
			return fmt.Errorf("classic AUTH payload = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "235 2.7.0 authentication successful"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "QUIT" {
			return fmt.Errorf("QUIT command = %q, err = %w", got, err)
		}

		return nil
	})
	defer waitServer()

	if err := checkSMTP(logger, clientConn, server); err != nil {
		t.Fatalf("SMTP check failed: %v", err)
	}

	if count := strings.Count(logBuffer.String(), "initial_response_fallback"); count != 1 {
		t.Fatalf("expected one initial-response fallback log, got %d in %s", count, logBuffer.String())
	}
}

func TestLMTPCredentialsUseLHLOAuthSelectionAndNoCredentialsStopsAfterCapabilities(t *testing.T) {
	t.Run("credentials", func(t *testing.T) {
		server := &config.BackendServer{
			Protocol:      "lmtp",
			Host:          "127.0.0.1",
			Port:          24,
			TestUsername:  "monitor",
			TestPassword:  "secret",
			AuthMechanism: config.BackendAuthMechanismPlain,
		}
		plainPayload := base64.StdEncoding.EncodeToString([]byte("\x00monitor\x00secret"))
		clientConn, waitServer := newTLSScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLine(conn, "220 lmtp.example.test LMTP"); err != nil {
				return err
			}

			if got, err := readTestLine(reader); err != nil || !strings.HasPrefix(got, "LHLO ") {
				return fmt.Errorf("LHLO command = %q, err = %w", got, err)
			}

			if err := writeTestLines(conn, "250-lmtp.example.test", "250-AUTH PLAIN", "250 OK"); err != nil {
				return err
			}

			if got, err := readTestLine(reader); err != nil || got != "AUTH PLAIN "+plainPayload {
				return fmt.Errorf("LMTP AUTH command = %q, err = %w", got, err)
			}

			if err := writeTestLine(conn, "235 2.7.0 authentication successful"); err != nil {
				return err
			}

			if got, err := readTestLine(reader); err != nil || got != "QUIT" {
				return fmt.Errorf("QUIT command = %q, err = %w", got, err)
			}

			return nil
		})
		defer waitServer()

		if err := checkSMTP(slog.Default(), clientConn, server); err != nil {
			t.Fatalf("LMTP check failed: %v", err)
		}
	})

	t.Run("no-credentials", func(t *testing.T) {
		server := &config.BackendServer{
			Protocol:      "lmtp",
			Host:          "127.0.0.1",
			Port:          24,
			AuthMechanism: config.BackendAuthMechanismPlain,
		}
		clientConn, waitServer := newTLSScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLine(conn, "220 lmtp.example.test LMTP"); err != nil {
				return err
			}

			if got, err := readTestLine(reader); err != nil || !strings.HasPrefix(got, "LHLO ") {
				return fmt.Errorf("LHLO command = %q, err = %w", got, err)
			}

			if err := writeTestLines(conn, "250-lmtp.example.test", "250-AUTH PLAIN", "250 OK"); err != nil {
				return err
			}

			if got, err := readTestLine(reader); err != nil || got != "QUIT" {
				return fmt.Errorf("expected no LMTP AUTH without credentials, got %q, err = %w", got, err)
			}

			return nil
		})
		defer waitServer()

		if err := checkSMTP(slog.Default(), clientConn, server); err != nil {
			t.Fatalf("LMTP no-credential check failed: %v", err)
		}
	})
}

func TestSMTPFamilyUpgradesWithSTARTTLSBeforeAuthentication(t *testing.T) {
	testCases := []struct {
		name            string
		protocol        string
		greeting        string
		capabilityLabel string
	}{
		{name: "smtp", protocol: "smtp", greeting: "220 smtp.example.test ESMTP", capabilityLabel: "EHLO"},
		{name: "lmtp", protocol: "lmtp", greeting: "220 lmtp.example.test LMTP", capabilityLabel: "LHLO"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := &config.BackendServer{
				Protocol:      testCase.protocol,
				Host:          "localhost",
				Port:          25,
				TestUsername:  "monitor",
				TestPassword:  "secret",
				AuthMechanism: config.BackendAuthMechanismPlain,
				TLSMode:       config.BackendTLSModeStartTLS,
				TLSSkipVerify: true,
			}
			plainPayload := base64.StdEncoding.EncodeToString([]byte("\x00monitor\x00secret"))
			clientConn, waitServer := newStartTLSScriptConn(t, func(conn net.Conn) error {
				reader := bufio.NewReader(conn)
				if err := writeTestLine(conn, testCase.greeting); err != nil {
					return err
				}

				if got, err := readTestLine(reader); err != nil || !strings.HasPrefix(got, testCase.capabilityLabel+" ") {
					return fmt.Errorf("pre-TLS %s command = %q, err = %w", testCase.capabilityLabel, got, err)
				}

				if err := writeTestLines(conn, "250-localhost", "250-STARTTLS", "250 AUTH LOGIN"); err != nil {
					return err
				}

				if got, err := readTestLine(reader); err != nil || got != "STARTTLS" {
					return fmt.Errorf("STARTTLS command = %q, err = %w", got, err)
				}

				return writeTestLine(conn, "220 2.0.0 ready to start TLS")
			}, func(conn net.Conn) error {
				reader := bufio.NewReader(conn)
				if got, err := readTestLine(reader); err != nil || !strings.HasPrefix(got, testCase.capabilityLabel+" ") {
					return fmt.Errorf("post-TLS %s command = %q, err = %w", testCase.capabilityLabel, got, err)
				}

				if err := writeTestLines(conn, "250-localhost", "250 AUTH PLAIN"); err != nil {
					return err
				}

				if got, err := readTestLine(reader); err != nil || got != "AUTH PLAIN "+plainPayload {
					return fmt.Errorf("protected AUTH command = %q, err = %w", got, err)
				}

				if err := writeTestLine(conn, "235 2.7.0 authentication successful"); err != nil {
					return err
				}

				if got, err := readTestLine(reader); err != nil || got != "QUIT" {
					return fmt.Errorf("QUIT command = %q, err = %w", got, err)
				}

				return nil
			})
			defer waitServer()

			if err := checkSMTP(slog.Default(), clientConn, server); err != nil {
				t.Fatalf("%s STARTTLS check failed: %v", testCase.protocol, err)
			}
		})
	}
}

func TestIMAPWithoutSASLIRUsesClassicExchange(t *testing.T) {
	server := &config.BackendServer{
		Protocol:      "imap",
		Host:          "127.0.0.1",
		Port:          993,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismLogin,
	}
	usernamePayload := base64.StdEncoding.EncodeToString([]byte("monitor"))
	passwordPayload := base64.StdEncoding.EncodeToString([]byte("secret"))
	clientConn, waitServer := newTLSScriptConn(t, func(conn net.Conn) error {
		reader := bufio.NewReader(conn)
		if err := writeTestLine(conn, "* OK imap.example.test ready"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "a1 CAPABILITY" {
			return fmt.Errorf("CAPABILITY command = %q, err = %w", got, err)
		}

		if err := writeTestLines(conn, "* CAPABILITY IMAP4rev1 AUTH=LOGIN", "a1 OK capability completed"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "a2 AUTHENTICATE LOGIN" {
			return fmt.Errorf("AUTHENTICATE command = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "+ VXNlcm5hbWU6"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != usernamePayload {
			return fmt.Errorf("username payload = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "+ UGFzc3dvcmQ6"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != passwordPayload {
			return fmt.Errorf("password payload = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "a2 OK authenticated"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "a3 LOGOUT" {
			return fmt.Errorf("LOGOUT command = %q, err = %w", got, err)
		}

		return nil
	})
	defer waitServer()

	if err := checkIMAP(slog.Default(), clientConn, server); err != nil {
		t.Fatalf("IMAP check failed: %v", err)
	}
}

func TestIMAPUpgradesWithSTARTTLSBeforeAuthentication(t *testing.T) {
	server := &config.BackendServer{
		Protocol:      "imap",
		Host:          "localhost",
		Port:          143,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismPlain,
		TLSMode:       config.BackendTLSModeStartTLS,
		TLSSkipVerify: true,
	}
	plainPayload := base64.StdEncoding.EncodeToString([]byte("\x00monitor\x00secret"))
	cert := testTLSCertificate(t)
	serverConn, clientConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer closeProtocolConn(serverConn)

		reader := bufio.NewReader(serverConn)
		if err := writeTestLine(serverConn, "* OK imap.example.test ready"); err != nil {
			errCh <- err

			return
		}

		if got, err := readTestLine(reader); err != nil || got != "a1 CAPABILITY" {
			errCh <- fmt.Errorf("pre-TLS CAPABILITY command = %q, err = %w", got, err)

			return
		}

		if err := writeTestLines(serverConn, "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN", "a1 OK capability completed"); err != nil {
			errCh <- err

			return
		}

		if got, err := readTestLine(reader); err != nil || got != "a2 STARTTLS" {
			errCh <- fmt.Errorf("STARTTLS command = %q, err = %w", got, err)

			return
		}

		if err := writeTestLine(serverConn, "a2 OK begin TLS negotiation"); err != nil {
			errCh <- err

			return
		}

		tlsConn := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			errCh <- err

			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		if got, err := readTestLine(tlsReader); err != nil || got != "a1 CAPABILITY" {
			errCh <- fmt.Errorf("post-TLS CAPABILITY command = %q, err = %w", got, err)

			return
		}

		if err := writeTestLines(tlsConn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR", "a1 OK capability completed"); err != nil {
			errCh <- err

			return
		}

		if got, err := readTestLine(tlsReader); err != nil || got != "a2 AUTHENTICATE PLAIN "+plainPayload {
			errCh <- fmt.Errorf("AUTHENTICATE command = %q, err = %w", got, err)

			return
		}

		if err := writeTestLine(tlsConn, "a2 OK authenticated"); err != nil {
			errCh <- err

			return
		}

		if got, err := readTestLine(tlsReader); err != nil || got != "a3 LOGOUT" {
			errCh <- fmt.Errorf("LOGOUT command = %q, err = %w", got, err)

			return
		}

		errCh <- nil
	}()

	if err := checkIMAP(slog.Default(), clientConn, server); err != nil {
		t.Fatalf("IMAP STARTTLS check failed: %v", err)
	}

	_ = clientConn.Close()

	if serverErr := <-errCh; serverErr != nil {
		t.Fatalf("scripted IMAP server failed: %v", serverErr)
	}
}

func TestPOP3AutoSelectsNativeUserPass(t *testing.T) {
	server := &config.BackendServer{
		Protocol:      "pop3",
		Host:          "127.0.0.1",
		Port:          995,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismAuto,
	}
	clientConn, waitServer := newTLSScriptConn(t, func(conn net.Conn) error {
		reader := bufio.NewReader(conn)
		if err := writeTestLine(conn, "+OK pop3.example.test ready"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "CAPA" {
			return fmt.Errorf("CAPA command = %q, err = %w", got, err)
		}

		if err := writeTestLines(conn, "+OK capability list follows", "USER", "."); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "USER monitor" {
			return fmt.Errorf("USER command = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "+OK user accepted"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "PASS secret" {
			return fmt.Errorf("PASS command = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "+OK maildrop locked"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "QUIT" {
			return fmt.Errorf("QUIT command = %q, err = %w", got, err)
		}

		return nil
	})
	defer waitServer()

	if err := checkPOP3(slog.Default(), clientConn, server); err != nil {
		t.Fatalf("POP3 check failed: %v", err)
	}
}

func TestPOP3UpgradesWithSTLSBeforeAuthentication(t *testing.T) {
	server := &config.BackendServer{
		Protocol:      "pop3",
		Host:          "localhost",
		Port:          110,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismUserPass,
		TLSMode:       config.BackendTLSModeStartTLS,
		TLSSkipVerify: true,
	}
	clientConn, waitServer := newStartTLSScriptConn(t, func(conn net.Conn) error {
		reader := bufio.NewReader(conn)
		if err := writeTestLine(conn, "+OK pop3.example.test ready"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "CAPA" {
			return fmt.Errorf("pre-TLS CAPA command = %q, err = %w", got, err)
		}

		if err := writeTestLines(conn, "+OK capability list follows", "STLS", "SASL LOGIN", "."); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "STLS" {
			return fmt.Errorf("STLS command = %q, err = %w", got, err)
		}

		return writeTestLine(conn, "+OK begin TLS negotiation")
	}, func(conn net.Conn) error {
		reader := bufio.NewReader(conn)
		if got, err := readTestLine(reader); err != nil || got != "CAPA" {
			return fmt.Errorf("post-TLS CAPA command = %q, err = %w", got, err)
		}

		if err := writeTestLines(conn, "+OK capability list follows", "USER", "."); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "USER monitor" {
			return fmt.Errorf("protected USER command = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "+OK user accepted"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "PASS secret" {
			return fmt.Errorf("protected PASS command = %q, err = %w", got, err)
		}

		if err := writeTestLine(conn, "+OK maildrop locked"); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || got != "QUIT" {
			return fmt.Errorf("QUIT command = %q, err = %w", got, err)
		}

		return nil
	})
	defer waitServer()

	if err := checkPOP3(slog.Default(), clientConn, server); err != nil {
		t.Fatalf("POP3 STLS check failed: %v", err)
	}
}

func TestMailProtocolsRequireSTARTTLSCapability(t *testing.T) {
	t.Run("smtp", func(t *testing.T) {
		testSMTPFamilyRequiresSTARTTLS(t, "smtp", 25, "220 smtp.example.test ESMTP", "EHLO ")
	})

	t.Run("lmtp", func(t *testing.T) {
		testSMTPFamilyRequiresSTARTTLS(t, "lmtp", 24, "220 lmtp.example.test LMTP", "LHLO ")
	})

	t.Run("pop3", func(t *testing.T) {
		server := plaintextAuthServer("pop3", 110)
		clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLine(conn, "+OK pop3.example.test ready"); err != nil {
				return err
			}

			if err := expectTestLine(reader, "CAPA"); err != nil {
				return err
			}

			return writeTestLines(conn, "+OK capability list follows", "USER", ".")
		})
		defer waitServer()

		assertUpgradeCapabilityError(t, checkPOP3(slog.Default(), clientConn, server), "STLS")
	})

	t.Run("imap", func(t *testing.T) {
		server := plaintextAuthServer("imap", 143)
		clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLine(conn, "* OK imap.example.test ready"); err != nil {
				return err
			}

			if err := expectTestLine(reader, "a1 CAPABILITY"); err != nil {
				return err
			}

			return writeTestLines(conn, "* CAPABILITY IMAP4rev1 AUTH=PLAIN", "a1 OK capability completed")
		})
		defer waitServer()

		assertUpgradeCapabilityError(t, checkIMAP(slog.Default(), clientConn, server), "STARTTLS")
	})
}

// testSMTPFamilyRequiresSTARTTLS verifies that SMTP-family checks reject missing upgrade capabilities.
func testSMTPFamilyRequiresSTARTTLS(t *testing.T, protocol string, port int, greeting string, helloPrefix string) {
	t.Helper()

	server := plaintextAuthServer(protocol, port)
	clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
		reader := bufio.NewReader(conn)
		if err := writeTestLine(conn, greeting); err != nil {
			return err
		}

		if got, err := readTestLine(reader); err != nil || !strings.HasPrefix(got, helloPrefix) {
			return fmt.Errorf("%s command = %q, err = %w", strings.TrimSpace(helloPrefix), got, err)
		}

		return writeTestLines(conn, "250-localhost", "250 AUTH PLAIN")
	})
	defer waitServer()

	assertUpgradeCapabilityError(t, checkSMTP(slog.Default(), clientConn, server), "STARTTLS")
}

func TestMailProtocolsFailWhenSTARTTLSIsRefused(t *testing.T) {
	for _, protocol := range []string{"smtp", "lmtp"} {
		t.Run(protocol, func(t *testing.T) {
			server := plaintextAuthServer(protocol, 25)
			clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
				reader := bufio.NewReader(conn)
				if err := writeTestLine(conn, "220 mail.example.test ready"); err != nil {
					return err
				}

				if _, err := readTestLine(reader); err != nil {
					return err
				}

				if err := writeTestLines(conn, "250-localhost", "250 STARTTLS"); err != nil {
					return err
				}

				if err := expectTestLine(reader, "STARTTLS"); err != nil {
					return err
				}

				return writeTestLine(conn, "454 4.7.0 TLS temporarily unavailable")
			})
			defer waitServer()

			assertUpgradeCapabilityError(t, checkSMTP(slog.Default(), clientConn, server), "STARTTLS")
		})
	}

	t.Run("pop3", func(t *testing.T) {
		server := plaintextAuthServer("pop3", 110)
		clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLine(conn, "+OK pop3.example.test ready"); err != nil {
				return err
			}

			if err := expectTestLine(reader, "CAPA"); err != nil {
				return err
			}

			if err := writeTestLines(conn, "+OK capability list follows", "STLS", "."); err != nil {
				return err
			}

			if err := expectTestLine(reader, "STLS"); err != nil {
				return err
			}

			return writeTestLine(conn, "-ERR TLS temporarily unavailable")
		})
		defer waitServer()

		assertUpgradeCapabilityError(t, checkPOP3(slog.Default(), clientConn, server), "STLS")
	})

	t.Run("imap", func(t *testing.T) {
		server := plaintextAuthServer("imap", 143)
		clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLine(conn, "* OK imap.example.test ready"); err != nil {
				return err
			}

			if err := expectTestLine(reader, "a1 CAPABILITY"); err != nil {
				return err
			}

			if err := writeTestLines(conn, "* CAPABILITY IMAP4rev1 STARTTLS", "a1 OK capability completed"); err != nil {
				return err
			}

			if err := expectTestLine(reader, "a2 STARTTLS"); err != nil {
				return err
			}

			return writeTestLine(conn, "a2 NO TLS temporarily unavailable")
		})
		defer waitServer()

		assertUpgradeCapabilityError(t, checkIMAP(slog.Default(), clientConn, server), "STARTTLS")
	})

	t.Run("sieve", func(t *testing.T) {
		server := plaintextAuthServer("sieve", 4190)
		clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLines(conn, `"IMPLEMENTATION" "test"`, `"STARTTLS"`, "OK"); err != nil {
				return err
			}

			if err := expectTestLine(reader, "STARTTLS"); err != nil {
				return err
			}

			return writeTestLine(conn, "NO")
		})
		defer waitServer()

		assertUpgradeCapabilityError(t, checkSieve(slog.Default(), clientConn, server), "STARTTLS")
	})
}

func TestSieveRechecksCapabilitiesAfterStartTLS(t *testing.T) {
	server := &config.BackendServer{
		Protocol:      "sieve",
		Host:          "localhost",
		Port:          4190,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismPlain,
		TLSMode:       config.BackendTLSModeStartTLS,
		TLSSkipVerify: true,
	}
	plainPayload := base64.StdEncoding.EncodeToString([]byte("\x00monitor\x00secret"))
	cert := testTLSCertificate(t)
	serverConn, clientConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer closeProtocolConn(serverConn)
		reader := bufio.NewReader(serverConn)
		if err := writeTestLines(serverConn, `"IMPLEMENTATION" "test"`, `"STARTTLS"`, "OK"); err != nil {
			errCh <- err

			return
		}

		if got, err := readTestLine(reader); err != nil || got != "STARTTLS" {
			errCh <- fmt.Errorf("STARTTLS command = %q, err = %w", got, err)

			return
		}

		if err := writeTestLine(serverConn, "OK"); err != nil {
			errCh <- err

			return
		}

		tlsConn := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			errCh <- err

			return
		}

		tlsReader := bufio.NewReader(tlsConn)
		if got, err := readTestLine(tlsReader); err != nil || got != "CAPABILITY" {
			errCh <- fmt.Errorf("post-TLS CAPABILITY command = %q, err = %w", got, err)

			return
		}

		if err := writeTestLines(tlsConn, `"SASL" "PLAIN"`, `"SASL-IR"`, "OK"); err != nil {
			errCh <- err

			return
		}

		if got, err := readTestLine(tlsReader); err != nil || got != `AUTHENTICATE "PLAIN" "`+plainPayload+`"` {
			errCh <- fmt.Errorf("AUTHENTICATE command = %q, err = %w", got, err)

			return
		}

		if err := writeTestLine(tlsConn, "OK"); err != nil {
			errCh <- err

			return
		}

		if got, err := readTestLine(tlsReader); err != nil || got != "LOGOUT" {
			errCh <- fmt.Errorf("LOGOUT command = %q, err = %w", got, err)

			return
		}

		errCh <- nil
	}()

	if err := checkSieve(slog.Default(), clientConn, server); err != nil {
		t.Fatalf("Sieve check failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("scripted Sieve server failed: %v", err)
	}
}

func TestSieveRequiresStartTLSCapabilityBeforeUpgrade(t *testing.T) {
	server := &config.BackendServer{
		Protocol:      "sieve",
		Host:          "localhost",
		Port:          4190,
		AuthMechanism: config.BackendAuthMechanismAuto,
		TLSSkipVerify: true,
	}
	serverConn, clientConn := net.Pipe()
	defer closeProtocolConn(clientConn)

	errCh := make(chan error, 1)
	go func() {
		defer closeProtocolConn(serverConn)

		reader := bufio.NewReader(serverConn)
		if err := writeTestLines(serverConn, `"IMPLEMENTATION" "test"`, "OK"); err != nil {
			errCh <- err

			return
		}

		if err := serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			errCh <- err

			return
		}

		line, err := readTestLine(reader)
		if err == nil {
			errCh <- fmt.Errorf("unexpected command before STARTTLS capability: %s", line)

			return
		}

		if netErr, ok := stderrors.AsType[net.Error](err); ok && netErr.Timeout() {
			errCh <- nil

			return
		}

		if stderrors.Is(err, io.ErrClosedPipe) {
			errCh <- nil

			return
		}

		errCh <- err
	}()

	err := checkSieve(slog.Default(), clientConn, server)
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected missing STARTTLS capability error, got %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("scripted Sieve server failed: %v", err)
	}
}

func TestSieveHonorsExplicitPlainAndImplicitModes(t *testing.T) {
	t.Run("plain-without-credentials", func(t *testing.T) {
		server := &config.BackendServer{
			Protocol: "sieve",
			Host:     "localhost",
			Port:     4190,
			TLSMode:  config.BackendTLSModePlain,
		}
		clientConn, waitServer := newPlainScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLines(conn, `"IMPLEMENTATION" "test"`, "OK"); err != nil {
				return err
			}

			return expectTestLine(reader, "LOGOUT")
		})
		defer waitServer()

		if err := checkSieve(slog.Default(), clientConn, server); err != nil {
			t.Fatalf("explicit plaintext Sieve check failed: %v", err)
		}
	})

	t.Run("implicit-with-credentials", func(t *testing.T) {
		server := &config.BackendServer{
			Protocol:      "sieve",
			Host:          "localhost",
			Port:          4190,
			TestUsername:  "monitor",
			TestPassword:  "secret",
			AuthMechanism: config.BackendAuthMechanismPlain,
			TLSMode:       config.BackendTLSModeImplicit,
			TLSSkipVerify: true,
		}
		plainPayload := base64.StdEncoding.EncodeToString([]byte("\x00monitor\x00secret"))
		clientConn, waitServer := newTLSScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			if err := writeTestLines(conn, `"IMPLEMENTATION" "test"`, `"SASL" "PLAIN"`, `"SASL-IR"`, "OK"); err != nil {
				return err
			}

			if got, err := readTestLine(reader); err != nil || got != `AUTHENTICATE "PLAIN" "`+plainPayload+`"` {
				return fmt.Errorf("AUTHENTICATE command = %q, err = %w", got, err)
			}

			if err := writeTestLine(conn, "OK"); err != nil {
				return err
			}

			return expectTestLine(reader, "LOGOUT")
		})
		defer waitServer()

		if err := checkSieve(slog.Default(), clientConn, server); err != nil {
			t.Fatalf("implicit TLS Sieve check failed: %v", err)
		}
	})
}

func TestHTTPUsesStaticBasicAdapterAndRejectsNonBasic(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		server := &config.BackendServer{
			Protocol:      "http",
			Host:          "localhost",
			RequestURI:    "/healthz",
			Port:          443,
			TestUsername:  "monitor",
			TestPassword:  "secret",
			AuthMechanism: config.BackendAuthMechanismAuto,
		}
		basicPayload := base64.StdEncoding.EncodeToString([]byte("monitor:secret"))
		clientConn, waitServer := newTLSScriptConn(t, func(conn net.Conn) error {
			reader := bufio.NewReader(conn)
			requestLine, err := readTestLine(reader)
			if err != nil || requestLine != "GET /healthz HTTP/1.1" {
				return fmt.Errorf("request line = %q, err = %w", requestLine, err)
			}

			headers := make([]string, 0, 4)
			for {
				line, err := readTestLine(reader)
				if err != nil {
					return err
				}

				if line == "" {
					break
				}

				headers = append(headers, line)
			}

			if !containsTestLine(headers, "Authorization: Basic "+basicPayload) {
				return fmt.Errorf("missing Basic auth header in %#v", headers)
			}

			return writeTestLines(conn, "HTTP/1.1 200 OK", "Content-Length: 0", "")
		})
		defer waitServer()

		if err := checkHTTP(slog.Default(), clientConn, server); err != nil {
			t.Fatalf("HTTP check failed: %v", err)
		}
	})

	t.Run("non-basic", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
		server := &config.BackendServer{
			Protocol:      "http",
			Host:          "localhost",
			RequestURI:    "/healthz",
			Port:          443,
			TestUsername:  "monitor",
			TestPassword:  "secret",
			AuthMechanism: config.BackendAuthMechanismLogin,
		}

		err := checkHTTP(logger, &probeOnlyConn{}, server)
		if err == nil {
			t.Fatal("expected HTTP LOGIN to fail before auth data is written")
		}

		var unavailable *AuthMechanismUnavailableError
		if !stderrors.As(err, &unavailable) {
			t.Fatalf("expected AuthMechanismUnavailableError, got %T: %v", err, err)
		}

		if !strings.Contains(logBuffer.String(), "Backend health-check auth mechanism unavailable") {
			t.Fatalf("expected unavailable mechanism log, got %s", logBuffer.String())
		}
	})
}

// authSelectorServer returns a minimal backend target for selector tests.
func authSelectorServer(protocol string, mechanism string) *config.BackendServer {
	return &config.BackendServer{
		Protocol:      protocol,
		Host:          "127.0.0.1",
		Port:          993,
		AuthMechanism: mechanism,
	}
}

// plaintextAuthServer returns a backend target that requires a protected authentication exchange.
func plaintextAuthServer(protocol string, port int) *config.BackendServer {
	return &config.BackendServer{
		Protocol:      protocol,
		Host:          "localhost",
		Port:          port,
		TestUsername:  "monitor",
		TestPassword:  "secret",
		AuthMechanism: config.BackendAuthMechanismPlain,
		TLSMode:       config.BackendTLSModeStartTLS,
		TLSSkipVerify: true,
	}
}

// assertUpgradeCapabilityError requires a fail-closed missing-upgrade error.
func assertUpgradeCapabilityError(t *testing.T, err error, capability string) {
	t.Helper()

	if err == nil || !strings.Contains(strings.ToUpper(err.Error()), capability) {
		t.Fatalf("expected missing %s capability error, got %v", capability, err)
	}
}

// newPlainScriptConn connects a protocol checker to one plaintext scripted backend.
func newPlainScriptConn(t *testing.T, server func(net.Conn) error) (net.Conn, func()) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer closeProtocolConn(serverConn)

		errCh <- server(serverConn)
	}()

	return clientConn, func() {
		t.Helper()

		_ = clientConn.Close()
		if err := <-errCh; err != nil && !stderrors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("scripted plaintext server failed: %v", err)
		}
	}
}

// expectTestLine requires one exact line from a scripted protocol peer.
func expectTestLine(reader *bufio.Reader, want string) error {
	got, err := readTestLine(reader)
	if err != nil || got != want {
		return fmt.Errorf("protocol line = %q, want %q, err = %w", got, want, err)
	}

	return nil
}

// newTLSScriptConn connects the protocol checker to a scripted TLS backend.
func newTLSScriptConn(t *testing.T, server func(net.Conn) error) (*tls.Conn, func()) {
	t.Helper()

	cert := testTLSCertificate(t)
	serverConn, clientConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer closeProtocolConn(serverConn)

		tlsConn := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			errCh <- err

			return
		}

		errCh <- server(tlsConn)
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake failed: %v", err)
	}

	return tlsConn, func() {
		t.Helper()

		_ = tlsConn.Close()
		if err := <-errCh; err != nil && !stderrors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("scripted TLS server failed: %v", err)
		}
	}
}

// newStartTLSScriptConn connects a protocol checker to a scripted plaintext-to-TLS backend.
func newStartTLSScriptConn(t *testing.T, beforeTLS func(net.Conn) error, afterTLS func(net.Conn) error) (net.Conn, func()) {
	t.Helper()

	return newUpgradableScriptConn(t, func(conn net.Conn) net.Conn { return conn }, beforeTLS, afterTLS)
}

// newProxyStartTLSScriptConn requires a PROXY header before the scripted plaintext-to-TLS exchange.
func newProxyStartTLSScriptConn(t *testing.T, beforeTLS func(net.Conn) error, afterTLS func(net.Conn) error) (net.Conn, func()) {
	t.Helper()

	return newUpgradableScriptConn(t, func(conn net.Conn) net.Conn {
		return proxyproto.NewConn(conn, func(proxyConn *proxyproto.Conn) {
			proxyConn.ProxyHeaderPolicy = proxyproto.REQUIRE
		})
	}, beforeTLS, afterTLS)
}

// newUpgradableScriptConn runs a protocol transcript before and after an in-band TLS upgrade.
func newUpgradableScriptConn(t *testing.T, wrap func(net.Conn) net.Conn, beforeTLS func(net.Conn) error, afterTLS func(net.Conn) error) (net.Conn, func()) {
	t.Helper()

	cert := testTLSCertificate(t)
	serverConn, clientConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer closeProtocolConn(serverConn)

		wrappedConn := wrap(serverConn)
		if err := beforeTLS(wrappedConn); err != nil {
			errCh <- err

			return
		}

		tlsConn := tls.Server(wrappedConn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			errCh <- err

			return
		}

		errCh <- afterTLS(tlsConn)
	}()

	return clientConn, func() {
		t.Helper()

		_ = clientConn.Close()
		if err := <-errCh; err != nil && !stderrors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("scripted STARTTLS server failed: %v", err)
		}
	}
}

// testTLSCertificate creates a short-lived self-signed certificate for TLS protocol tests.
func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate TLS private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create TLS certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load TLS certificate: %v", err)
	}

	return cert
}

// writeTestLine sends one CRLF-terminated line to a scripted protocol peer.
func writeTestLine(writer io.Writer, line string) error {
	_, err := fmt.Fprintf(writer, "%s\r\n", line)

	return err
}

// writeTestLines sends a sequence of CRLF-terminated lines to a scripted protocol peer.
func writeTestLines(writer io.Writer, lines ...string) error {
	for _, line := range lines {
		if err := writeTestLine(writer, line); err != nil {
			return err
		}
	}

	return nil
}

// readTestLine reads one CRLF-terminated line from a scripted protocol peer.
func readTestLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimRight(line, "\r\n"), nil
}

// containsTestLine reports whether the scripted transcript contains an exact line.
func containsTestLine(lines []string, want string) bool {
	return slices.Contains(lines, want)
}
