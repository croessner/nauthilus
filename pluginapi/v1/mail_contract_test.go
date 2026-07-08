// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"context"
	"reflect"
	"testing"
)

func TestMailContractCapabilityAndHostMethod(t *testing.T) {
	if CapabilityMail != Capability("mail") {
		t.Fatalf("CapabilityMail = %q, want mail", CapabilityMail)
	}

	hostType := reflect.TypeFor[Host]()
	mailMethod, ok := hostType.MethodByName("Mail")

	if !ok {
		t.Fatal("Host must expose Mail(scope string) Mailer")
	}

	if mailMethod.Type.NumIn() != 1 || mailMethod.Type.In(0).Kind() != reflect.String {
		t.Fatalf("Host.Mail input signature = %s, want scope string", mailMethod.Type)
	}

	if mailMethod.Type.NumOut() != 1 || mailMethod.Type.Out(0) != reflect.TypeFor[Mailer]() {
		t.Fatalf("Host.Mail output signature = %s, want Mailer", mailMethod.Type)
	}
}

func TestMailerSendContract(t *testing.T) {
	mailerType := reflect.TypeFor[Mailer]()
	sendMethod, ok := mailerType.MethodByName("Send")

	if !ok {
		t.Fatal("Mailer must expose Send(context.Context, MailMessage) error")
	}

	if sendMethod.Type.NumIn() != 2 ||
		sendMethod.Type.In(0) != reflect.TypeFor[context.Context]() ||
		sendMethod.Type.In(1) != reflect.TypeFor[MailMessage]() {
		t.Fatalf("Mailer.Send input signature = %s, want context and MailMessage", sendMethod.Type)
	}

	if sendMethod.Type.NumOut() != 1 || !sendMethod.Type.Out(0).Implements(reflect.TypeFor[error]()) {
		t.Fatalf("Mailer.Send output signature = %s, want error", sendMethod.Type)
	}
}

func TestMailMessageValueOnlyFields(t *testing.T) {
	messageType := reflect.TypeFor[MailMessage]()
	wantFields := []string{
		"Server",
		"HeloName",
		"Username",
		"Password",
		"From",
		"Subject",
		"Body",
		"To",
		"Port",
		"TLS",
		"StartTLS",
		"LMTP",
	}

	if messageType.NumField() != len(wantFields) {
		t.Fatalf("MailMessage field count = %d, want %d", messageType.NumField(), len(wantFields))
	}

	for _, fieldName := range wantFields {
		field, ok := messageType.FieldByName(fieldName)
		if !ok {
			t.Fatalf("MailMessage missing field %s", fieldName)
		}

		if !isMailMessageValueField(field.Type) {
			t.Fatalf("MailMessage.%s has type %s, want string, int, bool, or []string", fieldName, field.Type)
		}
	}
}

// isMailMessageValueField reports whether a mail request field stays value-only.
func isMailMessageValueField(fieldType reflect.Type) bool {
	switch fieldType.Kind() {
	case reflect.String, reflect.Int, reflect.Bool:
		return true
	case reflect.Slice:
		return fieldType.Elem().Kind() == reflect.String
	default:
		return false
	}
}
