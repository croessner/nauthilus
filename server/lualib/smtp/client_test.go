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

func TestSendMail(t *testing.T) {
	tests := []struct {
		name         string
		opts         *MailOptions
		sendMailFunc InternalSendMailFunc
		expectErr    bool
	}{
		{
			name: "valid input with CNs, no auth",
			opts: NewMailOptions(
				"localhost",
				25,
				"localhost",
				"",
				"",
				"\"Testuser\" <test@example.com>",
				[]string{"\"Recipient\" <recipient@example.com>"},
				"Subject",
				"Body",
				false,
				false,
				false,
			),
			sendMailFunc: FakeSendMail,
			expectErr:    false,
		},
		{
			name: "valid input, no auth",
			opts: NewMailOptions(
				"localhost",
				25,
				"localhost",
				"",
				"",
				"test@example.com",
				[]string{"recipient@example.com"},
				"Subject",
				"Body",
				false,
				false,
				false,
			),
			sendMailFunc: FakeSendMail,
			expectErr:    false,
		},
		{
			name: "valid input with umLauts in subject, no auth",
			opts: NewMailOptions(
				"localhost",
				25,
				"localhost",
				"",
				"",
				"test@example.com",
				[]string{"recipient@example.com"},
				"Subject contain ö, ä, ü, ß",
				"Body",
				false,
				false,
				false,
			),
			sendMailFunc: FakeSendMail,
			expectErr:    false,
		},
		{
			name: "valid input, no auth, many to",
			opts: NewMailOptions(
				"localhost",
				25,
				"localhost",
				"",
				"",
				"test@example.com",
				[]string{"recipient1@example.com", "recipient2@example.com"},
				"Subject",
				"Body",
				false,
				false,
				false,
			),
			sendMailFunc: FakeSendMail,
			expectErr:    false,
		},
		{
			name: "valid input, with auth",
			opts: NewMailOptions(
				"localhost",
				25,
				"localhost",
				"user",
				"pass",
				"test@example.com",
				[]string{"recipient@example.com"},
				"Subject",
				"Body",
				false,
				false,
				false,
			),
			sendMailFunc: FakeSendMail,
			expectErr:    false,
		},
		{
			name: "invalid From address",
			opts: NewMailOptions(
				"localhost",
				25,
				"localhost",
				"user",
				"pass",
				"test",
				[]string{"recipient@example.com"},
				"Subject",
				"Body",
				false,
				false,
				false,
			),
			sendMailFunc: FakeSendMail,
			expectErr:    true,
		},
		{
			name: "error from SendMail",
			opts: NewMailOptions(
				"localhost",
				25,
				"localhost",
				"user",
				"pass",
				"test@example.com",
				[]string{"recipient@example.com"},
				"Subject",
				"Body",
				false,
				false,
				false,
			),
			sendMailFunc: func(_ string, _ string, _ smtp.Auth, _ string, _ []string, _ []byte, _ bool, _ bool) error {
				return errors.New("error")
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := SendMail(tc.opts, tc.sendMailFunc)
			if (!tc.expectErr && err != nil) || (tc.expectErr && err == nil) {
				t.Fatalf("expected error %v, got %v", tc.expectErr, err)
			}
		})
	}
}
