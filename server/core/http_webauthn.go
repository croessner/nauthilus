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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/go-webauthn/webauthn/webauthn"
)

// InitWebAuthn initializes the global WebAuthn configuration using values
// from the environment/config. The legacy behavior (logging on error) is preserved.
func (b DefaultBootstrap) InitWebAuthn() error {
	var err error

	cfg := b.cfg
	idpCfg := cfg.GetIDP()
	serverCfg := cfg.GetServer()

	if !shouldInitWebAuthn(idpCfg, serverCfg) {
		return nil
	}

	rpID := resolvedWebAuthnRPID(idpCfg.WebAuthn.RPID, idpCfg.OIDC.Issuer)
	origins := resolvedWebAuthnOrigins(idpCfg.WebAuthn.RPOrigins, b.env.GetDevMode())

	logWebAuthnConfig(b, rpID, origins)

	webAuthn, err = webauthn.New(newWebAuthnConfig(idpCfg, rpID, origins))
	if err != nil {
		level.Error(b.logger).Log(
			definitions.LogKeyMsg, "Failed to create WebAuthn from environment",
			definitions.LogKeyError, err,
		)
	}

	return err
}

// shouldInitWebAuthn reports whether configured server features need WebAuthn bootstrap.
func shouldInitWebAuthn(idpCfg *config.IDPSection, serverCfg *config.ServerSection) bool {
	hasFrontend := serverCfg.Frontend.Enabled
	hasIDP := idpCfg.OIDC.Enabled || idpCfg.SAML2.Enabled
	hasWebAuthnConfig := idpCfg.WebAuthn.RPDisplayName != "" || idpCfg.WebAuthn.RPID != "" || len(idpCfg.WebAuthn.RPOrigins) > 0

	return hasFrontend || hasIDP || hasWebAuthnConfig
}

// resolvedWebAuthnRPID derives the RP ID from the issuer when the configured value is local.
func resolvedWebAuthnRPID(rpID string, issuer string) string {
	if rpID != "" && rpID != "localhost" {
		return rpID
	}

	if issuer == "" {
		return rpID
	}

	if u, err := url.Parse(issuer); err == nil {
		return u.Hostname()
	}

	return rpID
}

// resolvedWebAuthnOrigins adds developer localhost origins when dev mode is enabled.
func resolvedWebAuthnOrigins(origins []string, devMode bool) []string {
	if !devMode || slices.Contains(origins, "https://localhost:9443") {
		return origins
	}

	return append(origins, "https://localhost:9443", "http://localhost:9094")
}

// logWebAuthnConfig emits the resolved WebAuthn bootstrap values.
func logWebAuthnConfig(b DefaultBootstrap, rpID string, origins []string) {
	idpCfg := b.cfg.GetIDP()

	util.DebugModuleWithCfg(
		context.Background(),
		b.cfg,
		b.logger,
		definitions.DbgWebAuthn,
		definitions.LogKeyMsg, "WebAuthn config resolved",
		"rp_id", rpID,
		"rp_display_name", idpCfg.WebAuthn.RPDisplayName,
		"rp_origins", origins,
		"authenticator_attachment", idpCfg.WebAuthn.GetAuthenticatorAttachment(),
		"resident_key", idpCfg.WebAuthn.GetResidentKey(),
		"user_verification", idpCfg.WebAuthn.GetUserVerification(),
		"oidc_issuer", idpCfg.OIDC.Issuer,
		"dev_mode", b.env.GetDevMode(),
	)
}

// newWebAuthnConfig builds the runtime WebAuthn library configuration.
func newWebAuthnConfig(idpCfg *config.IDPSection, rpID string, origins []string) *webauthn.Config {
	return &webauthn.Config{
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
	}
}
