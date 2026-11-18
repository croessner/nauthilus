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

package supporthistory

import (
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// Subject names the person a support case is about. Login is a claim as typed; Account is a canonical account.
type Subject struct {
	Login   string `json:"login,omitempty"`
	Account string `json:"account,omitempty"`
}

// Window is a time window with inclusive From and exclusive Until (event time).
type Window struct {
	From  time.Time `json:"from"`
	Until time.Time `json:"until"`
}

// PageRequest selects one result page.
type PageRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// AttemptSearchFilter combines the window with optional anchor filters.
type AttemptSearchFilter struct {
	From         time.Time `json:"from"`
	Until        time.Time `json:"until"`
	ClientIP     string    `json:"client_ip,omitempty"`
	Protocol     string    `json:"protocol,omitempty"`
	OIDCClientID string    `json:"oidc_client_id,omitempty"`
	SAMLEntityID string    `json:"saml_entity_id,omitempty"`
}

// AttemptSearchRequest searches the recorded attempts of one subject.
type AttemptSearchRequest struct {
	Subject        Subject             `json:"subject"`
	Filter         AttemptSearchFilter `json:"filter"`
	Page           PageRequest         `json:"page"`
	SchemaVersion  string              `json:"schema_version"`
	AuditReference string              `json:"audit_reference,omitempty"`
}

// AttemptDetailRequest returns one attempt; Around is any instant of the attempt, for example its started_at.
type AttemptDetailRequest struct {
	Around         time.Time `json:"around"`
	Subject        *Subject  `json:"subject,omitempty"`
	SchemaVersion  string    `json:"schema_version"`
	AttemptID      string    `json:"attempt_id"`
	AuditReference string    `json:"audit_reference,omitempty"`
}

// invalid builds a request validation error.
func invalid(code ErrorCode) *Error {
	return newError(code, nil)
}

// normalized trims the subject values.
func (s Subject) normalized() Subject {
	return Subject{Login: strings.TrimSpace(s.Login), Account: strings.TrimSpace(s.Account)}
}

// validate requires at least one bounded subject value.
func (s Subject) validate() *Error {
	if s.Login == "" && s.Account == "" {
		return invalid(CodeInvalidRequest)
	}

	for _, value := range []string{s.Login, s.Account} {
		if err := boundedText(value, maxSubjectLength); err != nil {
			return err
		}
	}

	return nil
}

// validateWindow enforces ordering and the shared maximum of a window.
func validateWindow(from, until time.Time) *Error {
	if from.IsZero() || until.IsZero() || !from.Before(until) {
		return invalid(CodeInvalidRequest)
	}

	if until.Sub(from) > MaxWindow {
		return invalid(CodeWindowTooLarge)
	}

	return nil
}

// validateAuditReference accepts an empty or bounded ticket-like annotation.
func validateAuditReference(reference string) *Error {
	if supportaccess.ValidAuditReference(reference) {
		return nil
	}

	return invalid(CodeInvalidRequest)
}

// validateSchemaVersion accepts only the current schema version.
func validateSchemaVersion(version string) *Error {
	if version != SchemaVersion {
		return invalid(CodeInvalidRequest)
	}

	return nil
}

// pageLimit applies the default and the maximum of a page.
func pageLimit(requested, fallback, maximum int) (int, *Error) {
	switch {
	case requested == 0:
		return fallback, nil
	case requested < 0 || requested > maximum:
		return 0, invalid(CodeInvalidRequest)
	default:
		return requested, nil
	}
}

// canonicalIP parses an IP address into its canonical unmapped text form.
func canonicalIP(value string) (string, *Error) {
	if value == "" {
		return "", nil
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", invalid(CodeInvalidRequest)
	}

	return addr.Unmap().String(), nil
}

// boundedText rejects oversized, invalid UTF-8, or control-character values.
func boundedText(value string, maximum int) *Error {
	if len(value) > maximum || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return invalid(CodeInvalidRequest)
	}

	return nil
}

// validate normalizes and checks an attempt search request.
func (r *AttemptSearchRequest) validate() *Error {
	if err := validateSchemaVersion(r.SchemaVersion); err != nil {
		return err
	}

	r.Subject = r.Subject.normalized()
	if err := r.Subject.validate(); err != nil {
		return err
	}

	if err := validateWindow(r.Filter.From, r.Filter.Until); err != nil {
		return err
	}

	ip, err := canonicalIP(r.Filter.ClientIP)
	if err != nil {
		return err
	}

	r.Filter.ClientIP = ip

	for _, check := range []struct {
		value   string
		maximum int
	}{{r.Filter.Protocol, 64}, {r.Filter.OIDCClientID, 256}, {r.Filter.SAMLEntityID, 1024}} {
		if err = boundedText(check.value, check.maximum); err != nil {
			return err
		}
	}

	return validateAuditReference(r.AuditReference)
}

// validate normalizes and checks an attempt detail request; support callers must name a subject.
func (r *AttemptDetailRequest) validate(caller Caller) *Error {
	if err := validateSchemaVersion(r.SchemaVersion); err != nil {
		return err
	}

	if r.Around.IsZero() {
		return invalid(CodeInvalidRequest)
	}

	if r.Subject != nil {
		subject := r.Subject.normalized()
		if err := subject.validate(); err != nil {
			return err
		}

		r.Subject = &subject
	} else if !caller.has(permissionDetailRead) {
		return invalid(CodeInvalidRequest)
	}

	return validateAuditReference(r.AuditReference)
}

// anchorFilter converts the request filter into the store filter.
func (f AttemptSearchFilter) anchorFilter() AttemptFilter {
	return AttemptFilter{
		ClientIP:     f.ClientIP,
		Protocol:     strings.TrimSpace(f.Protocol),
		OIDCClientID: strings.TrimSpace(f.OIDCClientID),
		SAMLEntityID: strings.TrimSpace(f.SAMLEntityID),
	}
}
