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

package monitoring

import (
	"bufio"
	"crypto/tls"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
)

const (
	sieveStatusOK           = "OK"
	sieveStatusNo           = "NO"
	sieveStatusBye          = "BYE"
	sieveStatusContinuation = "+"
	protocolQuitCommand     = "QUIT"
	imapLogoutCommand       = "a3 LOGOUT"
)

// capabilityAuthSession is the narrow protocol-session contract used by shared auth checks.
type capabilityAuthSession interface {
	readGreeting() error
	discoverCapabilities() (AuthCapabilities, error)
	authenticate(AuthSelection) error
}

// capabilityAuthCheck runs the common greeting, capability discovery, TLS, and auth selection flow.
type capabilityAuthCheck struct {
	session capabilityAuthSession
	logger  *slog.Logger
	server  *config.BackendServer
	conn    net.Conn
	logout  string
}

// Check executes a capability-driven protocol health check with a best-effort logout.
func (c capabilityAuthCheck) Check() error {
	defer writeProtocolLine(c.conn, c.logout)

	if err := c.session.readGreeting(); err != nil {
		return err
	}

	capabilities, err := c.session.discoverCapabilities()
	if err != nil {
		return err
	}

	if !hasBackendCredentials(c.server) {
		return nil
	}

	if err := requireAuthTLS(c.logger, c.conn, strings.ToLower(c.server.Protocol)); err != nil {
		return err
	}

	selection, err := NewAuthSelector(c.logger, c.server, BackendCheckPhaseDeep).Select(capabilities)
	if err != nil {
		return err
	}

	return c.session.authenticate(selection)
}

// smtpSession owns the SMTP and LMTP protocol exchange for one backend connection.
type smtpSession struct {
	reader *textproto.Reader
	logger *slog.Logger
	server *config.BackendServer
	conn   net.Conn
}

// checkSMTP adapts the SMTP/LMTP session object to the connection monitor entry point.
func checkSMTP(logger *slog.Logger, conn net.Conn, server *config.BackendServer) error {
	session := newSMTPSession(logger, conn, server)

	return session.Check()
}

// newSMTPSession wires textproto parsing around an already prepared backend connection.
func newSMTPSession(logger *slog.Logger, conn net.Conn, server *config.BackendServer) *smtpSession {
	return &smtpSession{
		reader: textproto.NewReader(bufio.NewReader(conn)),
		logger: logger,
		server: server,
		conn:   conn,
	}
}

// Check runs the shared capability-auth flow for SMTP and LMTP.
func (s *smtpSession) Check() error {
	return capabilityAuthCheck{
		session: s,
		logger:  s.logger,
		server:  s.server,
		conn:    s.conn,
		logout:  protocolQuitCommand,
	}.Check()
}

// readGreeting validates the SMTP or LMTP banner before capability discovery.
func (s *smtpSession) readGreeting() error {
	greeting, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !hasStatusPrefix(greeting, "220") {
		return fmt.Errorf("S/LMTP greeting failed, response: %s", greeting)
	}

	return nil
}

// discoverCapabilities sends EHLO or LHLO and returns normalized AUTH capabilities.
func (s *smtpSession) discoverCapabilities() (AuthCapabilities, error) {
	command := "EHLO"
	if strings.EqualFold(s.server.Protocol, "lmtp") {
		command = "LHLO"
	}

	if _, err := fmt.Fprintf(s.conn, "%s localhost.localdomain\r\n", command); err != nil {
		return AuthCapabilities{}, err
	}

	lines, err := readSMTPResponseLines(s.reader)
	if err != nil {
		return AuthCapabilities{}, err
	}

	return ParseSMTPAuthCapabilities(lines), nil
}

// authenticate executes the selected mechanism and performs the single syntax-fallback retry when allowed.
func (s *smtpSession) authenticate(selection AuthSelection) error {
	err := s.executeAuth(selection)
	if err == nil {
		return nil
	}

	if fallback, ok := stderrors.AsType[*initialResponseRejectedError](err); ok && selection.InitialResponse {
		logInitialResponseFallback(s.logger, s.server, selection.Mechanism, fallback.response)
		selection.InitialResponse = false

		return s.executeAuth(selection)
	}

	return err
}

// executeAuth dispatches the selected SMTP-family mechanism to its concrete exchange.
func (s *smtpSession) executeAuth(selection AuthSelection) error {
	switch selection.Mechanism {
	case HealthAuthMechanismPlain:
		return s.executePlain(selection)
	case HealthAuthMechanismLogin:
		return s.executeLogin(selection)
	default:
		return fmt.Errorf("SMTP auth mechanism %s is not executable", selection.Mechanism)
	}
}

// executePlain performs SMTP-family SASL PLAIN in initial-response or classic form.
func (s *smtpSession) executePlain(selection AuthSelection) error {
	payload := plainInitialResponse(s.server.TestUsername, s.server.TestPassword)
	if selection.InitialResponse {
		if _, err := fmt.Fprintf(s.conn, "AUTH PLAIN %s\r\n", payload); err != nil {
			return err
		}

		response, err := s.reader.ReadLine()
		if err != nil {
			return err
		}

		if hasStatusPrefix(response, "235") {
			return nil
		}

		if isInitialResponseSyntaxRejection(response) {
			return &initialResponseRejectedError{response: response}
		}

		return fmt.Errorf("SMTP AUTH PLAIN failed: %s", response)
	}

	if _, err := fmt.Fprintf(s.conn, "AUTH PLAIN\r\n"); err != nil {
		return err
	}

	response, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !hasStatusPrefix(response, "334") {
		return fmt.Errorf("SMTP AUTH PLAIN failed: %s", response)
	}

	if _, err := fmt.Fprintf(s.conn, "%s\r\n", payload); err != nil {
		return err
	}

	response, err = s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !hasStatusPrefix(response, "235") {
		return fmt.Errorf("SMTP AUTH PLAIN failed: %s", response)
	}

	return nil
}

// executeLogin performs SMTP-family SASL LOGIN in initial-response or classic form.
func (s *smtpSession) executeLogin(selection AuthSelection) error {
	username := loginResponse(s.server.TestUsername)
	password := loginResponse(s.server.TestPassword)

	response, err := s.beginLogin(selection, username)
	if err != nil {
		return err
	}

	if selection.InitialResponse && isInitialResponseSyntaxRejection(response) {
		return &initialResponseRejectedError{response: response}
	}

	if !hasStatusPrefix(response, "334") {
		return fmt.Errorf("SMTP AUTH LOGIN failed: %s", response)
	}

	if !selection.InitialResponse {
		if err := s.sendLoginUsername(username); err != nil {
			return err
		}
	}

	return s.sendLoginPassword(password)
}

// beginLogin starts SMTP-family LOGIN and returns the first server challenge or status.
func (s *smtpSession) beginLogin(selection AuthSelection, username string) (string, error) {
	if selection.InitialResponse {
		if _, err := fmt.Fprintf(s.conn, "AUTH LOGIN %s\r\n", username); err != nil {
			return "", err
		}
	} else if _, err := fmt.Fprintf(s.conn, "AUTH LOGIN\r\n"); err != nil {
		return "", err
	}

	return s.reader.ReadLine()
}

// sendLoginUsername sends the LOGIN username response and waits for the password challenge.
func (s *smtpSession) sendLoginUsername(username string) error {
	if _, err := fmt.Fprintf(s.conn, "%s\r\n", username); err != nil {
		return err
	}

	response, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !hasStatusPrefix(response, "334") {
		return fmt.Errorf("SMTP AUTH LOGIN failed: %s", response)
	}

	return nil
}

// sendLoginPassword sends the LOGIN password response and requires successful authentication.
func (s *smtpSession) sendLoginPassword(password string) error {
	if _, err := fmt.Fprintf(s.conn, "%s\r\n", password); err != nil {
		return err
	}

	response, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !hasStatusPrefix(response, "235") {
		return fmt.Errorf("SMTP AUTH LOGIN failed: %s", response)
	}

	return nil
}

// ParseSMTPAuthCapabilities normalizes SMTP and LMTP AUTH capability forms.
func ParseSMTPAuthCapabilities(lines []string) AuthCapabilities {
	capabilities := newAuthCapabilitiesWithRaw("smtp ehlo", lines)

	for _, line := range lines {
		fields := strings.Fields(stripSMTPStatus(line))
		if len(fields) == 0 {
			continue
		}

		if mechanism, ok := strings.CutPrefix(strings.ToUpper(fields[0]), "AUTH="); ok {
			mechanisms := append([]string{mechanism}, fields[1:]...)

			addSMTPMechanisms(&capabilities, mechanisms)

			continue
		}

		if !strings.EqualFold(fields[0], "AUTH") {
			continue
		}

		addSMTPMechanisms(&capabilities, fields[1:])
	}

	return capabilities
}

// addSMTPMechanisms records every executable mechanism from one SMTP AUTH declaration.
func addSMTPMechanisms(capabilities *AuthCapabilities, mechanisms []string) {
	for _, mechanism := range mechanisms {
		addSMTPMechanism(capabilities, mechanism)
	}
}

// addSMTPMechanism records one SMTP-family mechanism when health checks can execute it.
func addSMTPMechanism(capabilities *AuthCapabilities, mechanism string) {
	normalized, ok := normalizeAdvertisedAuthMechanism(mechanism)
	if !ok || normalized == HealthAuthMechanismBasic || normalized == HealthAuthMechanismUserPass {
		return
	}

	capabilities.AddMechanism(normalized, true, false)
}

// imapSession owns the IMAP protocol exchange for one backend connection.
type imapSession struct {
	reader *textproto.Reader
	logger *slog.Logger
	server *config.BackendServer
	conn   net.Conn
}

// checkIMAP adapts the IMAP session object to the connection monitor entry point.
func checkIMAP(logger *slog.Logger, conn net.Conn, server *config.BackendServer) error {
	session := &imapSession{
		reader: textproto.NewReader(bufio.NewReader(conn)),
		logger: logger,
		server: server,
		conn:   conn,
	}

	return session.Check()
}

// Check runs the shared capability-auth flow for IMAP.
func (s *imapSession) Check() error {
	return capabilityAuthCheck{
		session: s,
		logger:  s.logger,
		server:  s.server,
		conn:    s.conn,
		logout:  imapLogoutCommand,
	}.Check()
}

// readGreeting validates the IMAP greeting before CAPABILITY discovery.
func (s *imapSession) readGreeting() error {
	greeting, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(greeting, "* OK") {
		return fmt.Errorf("IMAP greeting failed: %s", greeting)
	}

	return nil
}

// discoverCapabilities asks IMAP for CAPABILITY and normalizes AUTH tokens plus SASL-IR.
func (s *imapSession) discoverCapabilities() (AuthCapabilities, error) {
	if _, err := fmt.Fprintf(s.conn, "a1 CAPABILITY\r\n"); err != nil {
		return AuthCapabilities{}, err
	}

	lines, err := readIMAPTaggedResponse(s.reader, "a1")
	if err != nil {
		return AuthCapabilities{}, err
	}

	return ParseIMAPAuthCapabilities(lines), nil
}

// authenticate executes the selected IMAP SASL mechanism.
func (s *imapSession) authenticate(selection AuthSelection) error {
	switch selection.Mechanism {
	case HealthAuthMechanismPlain:
		return s.authenticatePlain(selection)
	case HealthAuthMechanismLogin:
		return s.authenticateLogin(selection)
	default:
		return fmt.Errorf("IMAP auth mechanism %s is not executable", selection.Mechanism)
	}
}

// authenticatePlain performs IMAP SASL PLAIN with SASL-IR only when selected.
func (s *imapSession) authenticatePlain(selection AuthSelection) error {
	payload := plainInitialResponse(s.server.TestUsername, s.server.TestPassword)
	if selection.InitialResponse {
		if _, err := fmt.Fprintf(s.conn, "a2 AUTHENTICATE PLAIN %s\r\n", payload); err != nil {
			return err
		}

		return s.expectTaggedOK("a2", "IMAP AUTHENTICATE PLAIN")
	}

	if _, err := fmt.Fprintf(s.conn, "a2 AUTHENTICATE PLAIN\r\n"); err != nil {
		return err
	}

	if err := s.expectContinuation("IMAP AUTHENTICATE PLAIN"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(s.conn, "%s\r\n", payload); err != nil {
		return err
	}

	return s.expectTaggedOK("a2", "IMAP AUTHENTICATE PLAIN")
}

// authenticateLogin performs IMAP SASL LOGIN with SASL-IR only when selected.
func (s *imapSession) authenticateLogin(selection AuthSelection) error {
	username := loginResponse(s.server.TestUsername)
	password := loginResponse(s.server.TestPassword)

	if selection.InitialResponse {
		if _, err := fmt.Fprintf(s.conn, "a2 AUTHENTICATE LOGIN %s\r\n", username); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(s.conn, "a2 AUTHENTICATE LOGIN\r\n"); err != nil {
		return err
	}

	if !selection.InitialResponse {
		if err := s.expectContinuation("IMAP AUTHENTICATE LOGIN"); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(s.conn, "%s\r\n", username); err != nil {
			return err
		}
	}

	if err := s.expectContinuation("IMAP AUTHENTICATE LOGIN"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(s.conn, "%s\r\n", password); err != nil {
		return err
	}

	return s.expectTaggedOK("a2", "IMAP AUTHENTICATE LOGIN")
}

// expectContinuation requires an IMAP continuation response for the active SASL exchange.
func (s *imapSession) expectContinuation(operation string) error {
	response, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(response, "+") {
		return fmt.Errorf("%s failed: %s", operation, response)
	}

	return nil
}

// expectTaggedOK reads until the tagged IMAP completion line and requires OK status.
func (s *imapSession) expectTaggedOK(tag string, operation string) error {
	for {
		response, err := s.reader.ReadLine()
		if err != nil {
			return err
		}

		if !strings.HasPrefix(strings.ToUpper(response), strings.ToUpper(tag)+" ") {
			continue
		}

		if !strings.Contains(strings.ToUpper(response), " OK") {
			return fmt.Errorf("%s failed: %s", operation, response)
		}

		return nil
	}
}

// ParseIMAPAuthCapabilities normalizes IMAP CAPABILITY authentication tokens.
func ParseIMAPAuthCapabilities(lines []string) AuthCapabilities {
	capabilities := newAuthCapabilitiesWithRaw("imap capability", lines)

	for _, line := range lines {
		fields := strings.FieldsSeq(line)
		for field := range fields {
			if strings.EqualFold(field, "SASL-IR") {
				capabilities.SASLIR = true
			}
		}
	}

	for _, line := range lines {
		fields := strings.FieldsSeq(line)
		for field := range fields {
			mechanism, ok := strings.CutPrefix(strings.ToUpper(field), "AUTH=")
			if !ok {
				continue
			}

			normalized, supported := normalizeAdvertisedAuthMechanism(mechanism)
			if !supported || normalized == HealthAuthMechanismBasic || normalized == HealthAuthMechanismUserPass {
				continue
			}

			capabilities.AddMechanism(normalized, capabilities.SASLIR, false)
		}
	}

	return capabilities
}

// pop3Session owns the POP3 protocol exchange for one backend connection.
type pop3Session struct {
	reader *textproto.Reader
	logger *slog.Logger
	server *config.BackendServer
	conn   net.Conn
}

// checkPOP3 adapts the POP3 session object to the connection monitor entry point.
func checkPOP3(logger *slog.Logger, conn net.Conn, server *config.BackendServer) error {
	session := &pop3Session{
		reader: textproto.NewReader(bufio.NewReader(conn)),
		logger: logger,
		server: server,
		conn:   conn,
	}

	return session.Check()
}

// Check runs the shared capability-auth flow for POP3.
func (s *pop3Session) Check() error {
	return capabilityAuthCheck{
		session: s,
		logger:  s.logger,
		server:  s.server,
		conn:    s.conn,
		logout:  protocolQuitCommand,
	}.Check()
}

// readGreeting validates the POP3 greeting before CAPA discovery.
func (s *pop3Session) readGreeting() error {
	greeting, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !isOkResponsePOP3(greeting) {
		return fmt.Errorf("POP3 greeting failed: %s", greeting)
	}

	return nil
}

// discoverCapabilities asks POP3 for CAPA and normalizes SASL plus native USER support.
func (s *pop3Session) discoverCapabilities() (AuthCapabilities, error) {
	if _, err := fmt.Fprintf(s.conn, "CAPA\r\n"); err != nil {
		return AuthCapabilities{}, err
	}

	lines, err := readPOP3CapabilityResponse(s.reader)
	if err != nil {
		return AuthCapabilities{}, err
	}

	return ParsePOP3AuthCapabilities(lines), nil
}

// authenticate executes the selected POP3 native or SASL mechanism.
func (s *pop3Session) authenticate(selection AuthSelection) error {
	switch selection.Mechanism {
	case HealthAuthMechanismUserPass:
		return s.authenticateUserPass()
	case HealthAuthMechanismPlain:
		return s.authenticateSASLPlain()
	case HealthAuthMechanismLogin:
		return s.authenticateSASLLogin()
	default:
		return fmt.Errorf("POP3 auth mechanism %s is not executable", selection.Mechanism)
	}
}

// authenticateUserPass performs native POP3 USER/PASS authentication.
func (s *pop3Session) authenticateUserPass() error {
	if _, err := fmt.Fprintf(s.conn, "USER %s\r\n", s.server.TestUsername); err != nil {
		return err
	}

	response, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !isOkResponsePOP3(response) {
		return fmt.Errorf("POP3 USER command failed: %s", response)
	}

	if _, err := fmt.Fprintf(s.conn, "PASS %s\r\n", s.server.TestPassword); err != nil {
		return err
	}

	response, err = s.reader.ReadLine()
	if err != nil {
		return fmt.Errorf("POP3 PASS command failed: %w", err)
	}

	if !isOkResponsePOP3(response) {
		return fmt.Errorf("POP3 PASS command failed: %s", response)
	}

	return nil
}

// authenticateSASLPlain performs POP3 SASL PLAIN through the classic challenge flow.
func (s *pop3Session) authenticateSASLPlain() error {
	if _, err := fmt.Fprintf(s.conn, "AUTH PLAIN\r\n"); err != nil {
		return err
	}

	if err := s.expectContinuation("POP3 AUTH PLAIN"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(s.conn, "%s\r\n", plainInitialResponse(s.server.TestUsername, s.server.TestPassword)); err != nil {
		return err
	}

	return s.expectOK("POP3 AUTH PLAIN")
}

// authenticateSASLLogin performs POP3 SASL LOGIN through the classic challenge flow.
func (s *pop3Session) authenticateSASLLogin() error {
	if _, err := fmt.Fprintf(s.conn, "AUTH LOGIN\r\n"); err != nil {
		return err
	}

	if err := s.expectContinuation("POP3 AUTH LOGIN"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(s.conn, "%s\r\n", loginResponse(s.server.TestUsername)); err != nil {
		return err
	}

	if err := s.expectContinuation("POP3 AUTH LOGIN"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(s.conn, "%s\r\n", loginResponse(s.server.TestPassword)); err != nil {
		return err
	}

	return s.expectOK("POP3 AUTH LOGIN")
}

// expectContinuation requires a POP3 continuation response for the active SASL exchange.
func (s *pop3Session) expectContinuation(operation string) error {
	response, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(response, "+") {
		return fmt.Errorf("%s failed: %s", operation, response)
	}

	return nil
}

// expectOK requires a POP3 positive completion response.
func (s *pop3Session) expectOK(operation string) error {
	response, err := s.reader.ReadLine()
	if err != nil {
		return err
	}

	if !isOkResponsePOP3(response) {
		return fmt.Errorf("%s failed: %s", operation, response)
	}

	return nil
}

// ParsePOP3AuthCapabilities normalizes POP3 CAPA authentication tokens.
func ParsePOP3AuthCapabilities(lines []string) AuthCapabilities {
	capabilities := newAuthCapabilitiesWithRaw("pop3 capa", lines)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if strings.EqualFold(fields[0], "USER") {
			capabilities.AddMechanism(HealthAuthMechanismUserPass, false, true)

			continue
		}

		if !strings.EqualFold(fields[0], "SASL") {
			continue
		}

		for _, field := range fields[1:] {
			normalized, ok := normalizeAdvertisedAuthMechanism(field)
			if !ok || normalized == HealthAuthMechanismBasic || normalized == HealthAuthMechanismUserPass {
				continue
			}

			capabilities.AddMechanism(normalized, false, false)
		}
	}

	return capabilities
}

// sieveSession owns the ManageSieve protocol exchange for one backend connection.
type sieveSession struct {
	reader *textproto.Reader
	logger *slog.Logger
	server *config.BackendServer
	conn   net.Conn
}

// checkSieve adapts the ManageSieve session object to the connection monitor entry point.
func checkSieve(logger *slog.Logger, conn net.Conn, server *config.BackendServer) error {
	session := &sieveSession{
		reader: textproto.NewReader(bufio.NewReader(conn)),
		logger: logger,
		server: server,
		conn:   conn,
	}

	return session.Check()
}

// Check runs greeting, STARTTLS, post-TLS capability discovery, and optional authentication.
func (s *sieveSession) Check() error {
	greeting, err := readSieveResponse(s.reader)
	if err != nil {
		_ = level.Error(s.logger).Log(
			definitions.LogKeyMsg, "Sieve greeting read failed",
			"host", s.server.Host,
			"protocol", "sieve",
			definitions.LogKeyError, err,
		)

		return err
	}

	if greeting.Status != sieveStatusOK {
		_ = level.Error(s.logger).Log(
			definitions.LogKeyMsg, "Sieve greeting not OK",
			"host", s.server.Host,
			"protocol", "sieve",
			"response", greeting.Status,
			definitions.LogKeyError, "Sieve greeting not OK",
		)

		return fmt.Errorf("sieve greeting failed: %s", greeting.Status)
	}

	if !hasSieveCapability(greeting.Lines, "STARTTLS") {
		return fmt.Errorf("sieve STARTTLS capability not advertised")
	}

	tlsConn, err := s.startTLS()
	if err != nil {
		return err
	}

	s.conn = tlsConn
	s.reader = textproto.NewReader(bufio.NewReader(tlsConn))

	defer closeProtocolConn(tlsConn)
	defer func() {
		writeProtocolLine(s.conn, "LOGOUT")
	}()

	capabilities, err := s.discoverCapabilities()
	if err != nil {
		return err
	}

	if !hasBackendCredentials(s.server) {
		return nil
	}

	selection, err := NewAuthSelector(s.logger, s.server, BackendCheckPhaseDeep).Select(capabilities)
	if err != nil {
		return err
	}

	return s.authenticate(selection)
}

// startTLS upgrades ManageSieve to TLS before authentication-capability evaluation.
func (s *sieveSession) startTLS() (*tls.Conn, error) {
	if _, err := fmt.Fprintf(s.conn, "STARTTLS\r\n"); err != nil {
		return nil, err
	}

	response, err := readSieveResponse(s.reader)
	if err != nil {
		_ = level.Error(s.logger).Log(
			definitions.LogKeyMsg, "Sieve STARTTLS read failed",
			"host", s.server.Host,
			"protocol", "sieve",
			definitions.LogKeyError, err,
		)

		return nil, err
	}

	if response.Status != sieveStatusOK {
		_ = level.Error(s.logger).Log(
			definitions.LogKeyMsg, "Sieve STARTTLS refused",
			"host", s.server.Host,
			"protocol", "sieve",
			"response", response.Status,
			definitions.LogKeyError, "Sieve STARTTLS refused",
		)

		return nil, fmt.Errorf("STARTTLS command failed: %s", response.Status)
	}

	tlsConn := tls.Client(s.conn, &tls.Config{
		InsecureSkipVerify: s.server.TLSSkipVerify,
		ServerName:         s.server.Host,
		MinVersion:         tls.VersionTLS12,
	})

	if err := tlsConn.Handshake(); err != nil {
		_ = level.Error(s.logger).Log(
			definitions.LogKeyMsg, "TLS handshake failed (sieve STARTTLS)",
			"host", s.server.Host,
			"protocol", "sieve",
			"skip_verify", s.server.TLSSkipVerify,
			definitions.LogKeyError, err,
		)

		return nil, fmt.Errorf("TLS handshake failed (sieve host=%s skip_verify=%t): %w", s.server.Host, s.server.TLSSkipVerify, err)
	}

	return tlsConn, nil
}

// discoverCapabilities asks ManageSieve for the post-TLS capability set.
func (s *sieveSession) discoverCapabilities() (AuthCapabilities, error) {
	if _, err := fmt.Fprintf(s.conn, "CAPABILITY\r\n"); err != nil {
		return AuthCapabilities{}, err
	}

	response, err := readSieveResponse(s.reader)
	if err != nil {
		return AuthCapabilities{}, err
	}

	if response.Status != sieveStatusOK {
		return AuthCapabilities{}, fmt.Errorf("sieve CAPABILITY failed: %s", response.Status)
	}

	return ParseSieveAuthCapabilities(response.Lines), nil
}

// authenticate executes the selected ManageSieve SASL mechanism.
func (s *sieveSession) authenticate(selection AuthSelection) error {
	switch selection.Mechanism {
	case HealthAuthMechanismPlain:
		return s.authenticatePlain(selection)
	case HealthAuthMechanismLogin:
		return s.authenticateLogin(selection)
	default:
		return fmt.Errorf("sieve auth mechanism %s is not executable", selection.Mechanism)
	}
}

// authenticatePlain performs ManageSieve SASL PLAIN with SASL-IR only when selected.
func (s *sieveSession) authenticatePlain(selection AuthSelection) error {
	payload := plainInitialResponse(s.server.TestUsername, s.server.TestPassword)
	if selection.InitialResponse {
		if _, err := fmt.Fprintf(s.conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", payload); err != nil {
			return err
		}

		return s.expectOK("Sieve AUTHENTICATE PLAIN")
	}

	if _, err := fmt.Fprintf(s.conn, "AUTHENTICATE \"PLAIN\"\r\n"); err != nil {
		return err
	}

	if err := s.expectContinuation("Sieve AUTHENTICATE PLAIN"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(s.conn, "\"%s\"\r\n", payload); err != nil {
		return err
	}

	return s.expectOK("Sieve AUTHENTICATE PLAIN")
}

// authenticateLogin performs ManageSieve SASL LOGIN with SASL-IR only when selected.
func (s *sieveSession) authenticateLogin(selection AuthSelection) error {
	username, password := loginCredentials(s.server)
	if selection.InitialResponse {
		if _, err := fmt.Fprintf(s.conn, "AUTHENTICATE \"LOGIN\" \"%s\"\r\n", username); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(s.conn, "AUTHENTICATE \"LOGIN\"\r\n"); err != nil {
		return err
	}

	if !selection.InitialResponse {
		if err := s.expectContinuation("Sieve AUTHENTICATE LOGIN"); err != nil {
			return err
		}

		if _, err := fmt.Fprintf(s.conn, "\"%s\"\r\n", username); err != nil {
			return err
		}
	}

	if err := s.expectContinuation("Sieve AUTHENTICATE LOGIN"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(s.conn, "\"%s\"\r\n", password); err != nil {
		return err
	}

	return s.expectOK("Sieve AUTHENTICATE LOGIN")
}

// expectContinuation requires a ManageSieve continuation or accepts an already completed OK.
func (s *sieveSession) expectContinuation(operation string) error {
	response, err := readSieveResponse(s.reader)
	if err != nil {
		return err
	}

	if response.Status == sieveStatusOK {
		return nil
	}

	if response.Status != "" {
		return fmt.Errorf("%s failed: %s", operation, response.Status)
	}

	return nil
}

// expectOK requires a ManageSieve OK completion response.
func (s *sieveSession) expectOK(operation string) error {
	response, err := readSieveResponse(s.reader)
	if err != nil {
		return err
	}

	if response.Status != sieveStatusOK {
		return fmt.Errorf("%s failed: %s", operation, response.Status)
	}

	return nil
}

// ParseSieveAuthCapabilities normalizes ManageSieve greeting and CAPABILITY auth tokens.
func ParseSieveAuthCapabilities(lines []string) AuthCapabilities {
	capabilities := newAuthCapabilitiesWithRaw("sieve capability", lines)

	for _, line := range lines {
		tokens := parseQuotedCapabilityTokens(line)
		if len(tokens) == 0 {
			continue
		}

		for _, token := range tokens {
			if strings.EqualFold(token, "SASL-IR") {
				capabilities.SASLIR = true
			}
		}
	}

	for _, line := range lines {
		tokens := parseQuotedCapabilityTokens(line)
		if len(tokens) < 2 || !strings.EqualFold(tokens[0], "SASL") {
			continue
		}

		for token := range strings.FieldsSeq(strings.Join(tokens[1:], " ")) {
			normalized, ok := normalizeAdvertisedAuthMechanism(token)
			if !ok || normalized == HealthAuthMechanismBasic || normalized == HealthAuthMechanismUserPass {
				continue
			}

			capabilities.AddMechanism(normalized, capabilities.SASLIR, false)
		}
	}

	return capabilities
}

// hasSieveCapability reports whether a greeting or capability block contains one capability token.
func hasSieveCapability(lines []string, capability string) bool {
	for _, line := range lines {
		for _, token := range parseQuotedCapabilityTokens(line) {
			if strings.EqualFold(token, capability) {
				return true
			}
		}
	}

	return false
}

// checkHTTP performs an HTTP reachability check with selector-driven Basic authentication.
func checkHTTP(logger *slog.Logger, conn net.Conn, server *config.BackendServer) error {
	authHeader := ""

	if hasBackendCredentials(server) {
		capabilities := NewAuthCapabilities("http static")
		capabilities.SupportsCapabilities = false
		capabilities.AddMechanism(HealthAuthMechanismBasic, false, false)

		selection, err := NewAuthSelector(logger, server, BackendCheckPhaseDeep).Select(capabilities)
		if err != nil {
			return err
		}

		if selection.Mechanism != HealthAuthMechanismBasic {
			return fmt.Errorf("HTTP auth mechanism %s is not executable", selection.Mechanism)
		}

		if err := requireAuthTLS(logger, conn, "http"); err != nil {
			return err
		}

		authHeader = "Authorization: Basic " + basicAuthResponse(server.TestUsername, server.TestPassword) + "\r\n"
	}

	requestURI := server.RequestURI
	if requestURI == "" {
		requestURI = "/"
	}

	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n%sUser-Agent: Nauthilus\r\nAccept: */*\r\n\r\n", requestURI, server.Host, authHeader); err != nil {
		return err
	}

	reader := textproto.NewReader(bufio.NewReader(conn))

	statusLine, err := reader.ReadLine()
	if err != nil {
		return err
	}

	if !isOkResponseHTTP(statusLine) {
		return fmt.Errorf("HTTP request failed: %s", statusLine)
	}

	_, err = reader.ReadMIMEHeader()

	return err
}

type initialResponseRejectedError struct {
	response string
}

// Error returns the rejected server response without exposing auth payloads.
func (e *initialResponseRejectedError) Error() string {
	return "initial response rejected: " + e.response
}

// sieveResponse contains one complete ManageSieve response block.
type sieveResponse struct {
	Lines  []string
	Status string
}

// readSMTPResponseLines reads a complete EHLO or LHLO response block.
func readSMTPResponseLines(reader *textproto.Reader) ([]string, error) {
	lines := make([]string, 0, 4)

	for {
		line, err := reader.ReadLine()
		if err != nil {
			return nil, err
		}

		lines = append(lines, line)
		if hasSMTPFinalLine(line) {
			if !hasStatusPrefix(line, "250") {
				return nil, fmt.Errorf("L/SMTP EHLO/LHLO failed, response: %s", line)
			}

			return lines, nil
		}

		if len(line) > 0 && line[0] >= '4' {
			return nil, fmt.Errorf("L/SMTP EHLO/LHLO failed, response: %s", line)
		}
	}
}

// readIMAPTaggedResponse reads IMAP lines until the requested tag completes.
func readIMAPTaggedResponse(reader *textproto.Reader, tag string) ([]string, error) {
	lines := make([]string, 0, 4)

	for {
		line, err := reader.ReadLine()
		if err != nil {
			return nil, err
		}

		lines = append(lines, line)
		upperLine := strings.ToUpper(line)
		upperTag := strings.ToUpper(tag) + " "

		if !strings.HasPrefix(upperLine, upperTag) {
			continue
		}

		if !strings.Contains(upperLine, " OK") {
			return nil, fmt.Errorf("IMAP command %s failed: %s", tag, line)
		}

		return lines, nil
	}
}

// readPOP3CapabilityResponse reads a complete multiline CAPA response.
func readPOP3CapabilityResponse(reader *textproto.Reader) ([]string, error) {
	status, err := reader.ReadLine()
	if err != nil {
		return nil, err
	}

	if !isOkResponsePOP3(status) {
		return nil, fmt.Errorf("POP3 CAPA command failed: %s", status)
	}

	lines := make([]string, 0, 4)

	for {
		line, err := reader.ReadLine()
		if err != nil {
			return nil, err
		}

		if line == "." {
			return lines, nil
		}

		lines = append(lines, line)
	}
}

// readSieveResponse reads a ManageSieve response block and separates capability lines from status.
func readSieveResponse(reader *textproto.Reader) (sieveResponse, error) {
	response := sieveResponse{Lines: make([]string, 0, 4)}

	for {
		line, err := reader.ReadLine()
		if err != nil {
			return response, err
		}

		status := sieveStatus(line)
		if status != "" {
			response.Status = status

			return response, nil
		}

		response.Lines = append(response.Lines, line)
	}
}

// sieveStatus classifies one ManageSieve line as terminal status, continuation, or capability data.
func sieveStatus(line string) string {
	trimmed := strings.TrimSpace(line)

	for _, status := range []string{sieveStatusOK, sieveStatusNo, sieveStatusBye} {
		if trimmed == status || strings.HasPrefix(trimmed, status+" ") {
			return status
		}
	}

	if strings.HasPrefix(trimmed, `"`) {
		return ""
	}

	if strings.HasPrefix(trimmed, "+") {
		return sieveStatusContinuation
	}

	return ""
}

// parseQuotedCapabilityTokens extracts quoted ManageSieve capability fields while keeping unquoted fallback fields.
func parseQuotedCapabilityTokens(line string) []string {
	remaining := strings.TrimSpace(line)
	tokens := make([]string, 0, 2)

	for remaining != "" {
		if !strings.HasPrefix(remaining, `"`) {
			fields := strings.Fields(remaining)
			tokens = append(tokens, fields...)

			return tokens
		}

		remaining = strings.TrimPrefix(remaining, `"`)

		end := strings.Index(remaining, `"`)
		if end < 0 {
			return tokens
		}

		tokens = append(tokens, remaining[:end])
		remaining = strings.TrimSpace(remaining[end+1:])
	}

	return tokens
}

// hasSMTPFinalLine reports whether an SMTP-family reply line terminates a multiline response.
func hasSMTPFinalLine(line string) bool {
	return len(line) >= 4 && line[3] == ' '
}

// hasStatusPrefix reports whether a protocol response starts with the expected status code.
func hasStatusPrefix(line string, code string) bool {
	return len(line) >= len(code) && strings.HasPrefix(line, code)
}

// stripSMTPStatus removes the leading reply code and separator from an SMTP-family capability line.
func stripSMTPStatus(line string) string {
	if len(line) < 4 {
		return line
	}

	if line[0] < '0' || line[0] > '9' || line[1] < '0' || line[1] > '9' || line[2] < '0' || line[2] > '9' {
		return line
	}

	return strings.TrimSpace(line[4:])
}

// isInitialResponseSyntaxRejection identifies replies that warrant one classic-exchange retry.
func isInitialResponseSyntaxRejection(response string) bool {
	return hasStatusPrefix(response, "500") || hasStatusPrefix(response, "501")
}

// isOkResponsePOP3 reports whether a POP3 response is positive.
func isOkResponsePOP3(response string) bool {
	return strings.HasPrefix(response, "+OK")
}

// isOkResponseHTTP reports whether an HTTP status line is a successful health response.
func isOkResponseHTTP(response string) bool {
	return strings.HasPrefix(response, "HTTP/1.1 200") || strings.HasPrefix(response, "HTTP/1.0 200")
}

// hasBackendCredentials reports whether a backend target has credentials for deep authentication.
func hasBackendCredentials(server *config.BackendServer) bool {
	return server != nil && server.TestUsername != "" && server.TestPassword != ""
}

// loginCredentials returns base64-encoded username and password values for LOGIN exchanges.
func loginCredentials(server *config.BackendServer) (string, string) {
	if server == nil {
		return "", ""
	}

	return loginResponse(server.TestUsername), loginResponse(server.TestPassword)
}

// writeProtocolLine sends a best-effort protocol command during teardown.
func writeProtocolLine(conn net.Conn, line string) {
	if conn == nil || line == "" {
		return
	}

	_, _ = fmt.Fprintf(conn, "%s\r\n", line)
}

// closeProtocolConn closes a protocol connection during deferred cleanup.
func closeProtocolConn(conn net.Conn) {
	if conn == nil {
		return
	}

	_ = conn.Close()
}

// requireAuthTLS rejects credential-bearing checks on non-TLS connections.
func requireAuthTLS(logger *slog.Logger, conn net.Conn, protocol string) error {
	if isTLSConnection(conn) {
		return nil
	}

	_ = level.Warn(logger).Log(
		definitions.LogKeyMsg, "missing TLS on connection where required",
		"protocol", protocol,
	)

	return errors.ErrMissingTLS
}
