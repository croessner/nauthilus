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
	"context"
	"net/url"
	"slices"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"

	"github.com/go-webauthn/webauthn/webauthn"
)

// InitWebAuthn initializes the global WebAuthn configuration using values
// from the environment/config. The legacy behavior (logging on error) is preserved.
func (b DefaultBootstrap) InitWebAuthn() error {
	var err error
	cfg := b.cfg
	idpCfg := cfg.GetIdP()
	serverCfg := cfg.GetServer()

	hasFrontend := serverCfg.Frontend.Enabled
	hasIDP := idpCfg.OIDC.Enabled || idpCfg.SAML2.Enabled
	hasWebAuthnConfig := idpCfg.WebAuthn.RPDisplayName != "" || idpCfg.WebAuthn.RPID != "" || len(idpCfg.WebAuthn.RPOrigins) > 0

	if !hasFrontend && !hasIDP && !hasWebAuthnConfig {
		return nil
	}

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
		localhostFound := slices.Contains(origins, "https://localhost:9443")

		if !localhostFound {
			origins = append(origins, "https://localhost:9443", "http://localhost:9094")
		}
	}

	util.DebugModuleWithCfg(
		context.Background(),
		cfg,
		b.logger,
		definitions.DbgWebAuthn,
		definitions.LogKeyMsg, "WebAuthn config resolved",
		"rp_id", rpID,
		"rp_display_name", idpCfg.WebAuthn.RPDisplayName,
		"rp_origins", origins,
		"oidc_issuer", idpCfg.OIDC.Issuer,
		"dev_mode", b.env.GetDevMode(),
	)

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
