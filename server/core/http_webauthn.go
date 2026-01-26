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

package core

import (
	"net/url"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/go-webauthn/webauthn/webauthn"
)

// InitWebAuthn initializes the global WebAuthn configuration using values
// from the environment/config. The legacy behavior (logging on error) is preserved.
func (b DefaultBootstrap) InitWebAuthn() error {
	var err error
	cfg := b.cfg
	idpCfg := cfg.GetIdP()

	rpID := idpCfg.WebAuthn.RPID
	origins := idpCfg.WebAuthn.RPOrigins

	// If RPID is localhost (our new default) or empty, try to get a better one from IdP issuer
	if rpID == "" || rpID == "localhost" {
		issuer := idpCfg.OIDC.Issuer
		if issuer != "" {
			if u, err := url.Parse(issuer); err == nil {
				rpID = u.Hostname()
			}
		}
	}

	// Always ensure localhost is in origins if we are in developer mode
	if b.env.GetDevMode() {
		localhostFound := false

		for _, o := range origins {
			if o == "https://localhost:9443" {
				localhostFound = true

				break
			}
		}

		if !localhostFound {
			origins = append(origins, "https://localhost:9443", "http://localhost:9094")
		}
	}

	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: idpCfg.WebAuthn.RPDisplayName,
		RPID:          rpID,
		RPOrigins:     origins,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
		},
	})

	if err != nil {
		level.Error(b.logger).Log(
			definitions.LogKeyMsg, "Failed to create WebAuthn from environment",
			definitions.LogKeyError, err,
		)
	}

	return err
}
