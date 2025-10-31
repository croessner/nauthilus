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

//go:build hydra
// +build hydra

package core

import (
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/spf13/viper"
)

// InitWebAuthn initializes the global WebAuthn configuration using values
// from the environment/config. The legacy behavior (logging on error) is preserved.
func (DefaultBootstrap) InitWebAuthn() error {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: viper.GetString("webauthn_display_name"),
		RPID:          viper.GetString("webauthn_rp_id"),
		RPOrigins:     viper.GetStringSlice("webauthn_rp_origins"),
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
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Failed to create WebAuthn from environment",
			definitions.LogKeyError, err,
		)
	}

	return err
}
