package backend

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// User represents the user model
type User struct {
	Id          string `redis:"Id"`
	Name        string `redis:"name"`
	DisplayName string `redis:"display_name"`

	Credentials []webauthn.Credential `redis:"credentials"`
}

// NewUser creates and returns a new User
func NewUser(name string, displayName string, id string) *User {
	user := &User{}
	user.Id = id
	user.Name = name
	user.DisplayName = displayName
	// user.Credentials = []webauthn.Credential{}

	return user
}

// WebAuthnID returns the user's ID
func (u *User) WebAuthnID() []byte {
	return []byte(u.Id)
}

// WebAuthnName returns the user's username
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon is not (yet) implemented
func (u *User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the user
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
