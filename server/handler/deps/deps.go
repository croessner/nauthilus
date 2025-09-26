package deps

import (
	kitlog "github.com/go-kit/log"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/croessner/nauthilus/server/config"
)

// Services is an optional interface that can be expanded to hold business-layer services
// so that HTTP handlers stay thin and transport-agnostic.
type Services interface {
	// Define service interfaces here as needed
}

// Deps aggregates top-level dependencies to be injected into handler modules.
// Keep it minimal initially to avoid large refactors while enabling future DI.
type Deps struct {
	Cfg      config.File
	Logger   kitlog.Logger
	WebAuthn *webauthn.WebAuthn
	Svc      Services
}
