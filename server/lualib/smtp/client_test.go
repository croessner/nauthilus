// Copyright (C) 2024 Christian Rößner
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

package smtp

import (
	"errors"
	"fmt"
	"net/smtp"
	"testing"
)

func FakeSendMail(_ string, _ string, _ smtp.Auth, _ string, _ []string, body []byte, _ bool, _ bool) error {
	fmt.Println(string(body))

	return nil
}

type sendMailCase struct {
	name         string
	opts         *MailOptions
	sendMailFunc InternalSendMailFunc
	expectErr    bool
}

func TestSendMail(t *testing.T) {
	for _, tc := range sendMailCases() {
		t.Run(tc.name, func(t *testing.T) {
			err := SendMail(tc.opts, tc.sendMailFunc)
			if (!tc.expectErr && err != nil) || (tc.expectErr && err == nil) {
				t.Fatalf("expected error %v, got %v", tc.expectErr, err)
			}
		})
	}
}

// sendMailCases returns the success and failure scenarios for SendMail.
func sendMailCases() []sendMailCase {
	return append(validSendMailCases(), invalidSendMailCases()...)
}

// validSendMailCases returns successful SendMail input variants.
func validSendMailCases() []sendMailCase {
	return []sendMailCase{
		{
			name:         "valid input with CNs, no auth",
			opts:         testMailOptions("", "", "\"Testuser\" <test@example.com>", []string{"\"Recipient\" <recipient@example.com>"}, "Subject"),
			sendMailFunc: FakeSendMail,
		},
		{
			name:         "valid input, no auth",
			opts:         testMailOptions("", "", "test@example.com", []string{"recipient@example.com"}, "Subject"),
			sendMailFunc: FakeSendMail,
		},
		{
			name:         "valid input with umLauts in subject, no auth",
			opts:         testMailOptions("", "", "test@example.com", []string{"recipient@example.com"}, "Subject contain ö, ä, ü, ß"),
			sendMailFunc: FakeSendMail,
		},
		{
			name:         "valid input, no auth, many to",
			opts:         testMailOptions("", "", "test@example.com", []string{"recipient1@example.com", "recipient2@example.com"}, "Subject"),
			sendMailFunc: FakeSendMail,
		},
		{
			name:         "valid input, with auth",
			opts:         testMailOptions("user", "pass", "test@example.com", []string{"recipient@example.com"}, "Subject"),
			sendMailFunc: FakeSendMail,
		},
	}
}

// invalidSendMailCases returns failing SendMail input variants.
func invalidSendMailCases() []sendMailCase {
	return []sendMailCase{
		{
			name:         "invalid From address",
			opts:         testMailOptions("user", "pass", "test", []string{"recipient@example.com"}, "Subject"),
			sendMailFunc: FakeSendMail,
			expectErr:    true,
		},
		{
			name:         "error from SendMail",
			opts:         testMailOptions("user", "pass", "test@example.com", []string{"recipient@example.com"}, "Subject"),
			sendMailFunc: failingSendMail,
			expectErr:    true,
		},
	}
}

// testMailOptions builds the common SMTP mail options used by SendMail tests.
func testMailOptions(username string, password string, from string, to []string, subject string) *MailOptions {
	return NewMailOptions("localhost", 25, "localhost", username, password, from, to, subject, "Body", false, false, false)
}

// failingSendMail simulates a lower-level SMTP transport failure.
func failingSendMail(_ string, _ string, _ smtp.Auth, _ string, _ []string, _ []byte, _ bool, _ bool) error {
	return errors.New("error")
}
