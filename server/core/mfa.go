package core

import "github.com/croessner/nauthilus/server/config"

// MFA is an interface that stores some information for multi factor authentication.
type MFA interface {
	// GetValue returns the MFA value as a string.
	getValue() string

	// SetValue sets an MFA value.
	setValue(string)
}

type TOTPSecret struct {
	value string
}

func (t *TOTPSecret) getValue() string {
	return t.value
}

func (t *TOTPSecret) setValue(value string) {
	t.value = value
}

func (t *TOTPSecret) getLDAPTOTPSecret(protocol *config.LDAPSearchProtocol) string {
	return protocol.TOTPSecretField
}

func NewTOTPSecret(value string) *TOTPSecret {
	totpObj := &TOTPSecret{}
	totpObj.setValue(value)

	return totpObj
}

type WebAuthn struct {
	Value string
}

func (w *WebAuthn) getValue() string {
	return w.Value
}

func (w *WebAuthn) setValue(value string) {
	w.Value = value
}

func (w *WebAuthn) getLDAPUniqueUserID(protocol *config.LDAPSearchProtocol) string {
	return protocol.UniqueUserIDField
}

func NewWebAuthn(value string) *WebAuthn {
	webAuthNObj := &WebAuthn{}
	webAuthNObj.setValue(value)

	return webAuthNObj
}
