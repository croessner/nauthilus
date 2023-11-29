package core

import "github.com/croessner/nauthilus/server/config"

// MFA is an interface that stores some information for multi factor authentication.
type MFA interface {
	// GetValue returns the MFA value as a string.
	GetValue() string

	// SetValue sets an MFA value.
	SetValue(string)
}

type TOTPSecret struct {
	value string
}

func (t *TOTPSecret) GetValue() string {
	return t.value
}

func (t *TOTPSecret) SetValue(value string) {
	t.value = value
}

func (t *TOTPSecret) GetLDAPTOTPSecret(protocol *config.LDAPSearchProtocol) string {
	return protocol.TOTPSecretField
}

func (t *TOTPSecret) GetSQLTOTPSecret(protocol *config.SQLSearchProtocol) string {
	return protocol.TOTPSecret
}

func NewTOTPSecret(value string) *TOTPSecret {
	totpObj := &TOTPSecret{}
	totpObj.SetValue(value)

	return totpObj
}

type WebAuthn struct {
	Value string
}

func (w *WebAuthn) GetValue() string {
	return w.Value
}

func (w *WebAuthn) SetValue(value string) {
	w.Value = value
}

func (w *WebAuthn) GetLDAPUniqueUserID(protocol *config.LDAPSearchProtocol) string {
	return protocol.UniqueUserIDField
}

func (w *WebAuthn) GetSQLUniqueUserID(protocol *config.SQLSearchProtocol) string {
	return protocol.UniqueUserIDField
}

func NewWebAuthn(value string) *WebAuthn {
	webAuthNObj := &WebAuthn{}
	webAuthNObj.SetValue(value)

	return webAuthNObj
}
