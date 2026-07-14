// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package localizationfx wires declarative policy catalogs into startup and reload handling.
package localizationfx

import (
	"github.com/croessner/nauthilus/v3/server/app/reloadfx"

	"go.uber.org/fx"
)

// Module registers policy localization reload support.
func Module() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				NewDefaultReloader,
				fx.As(new(reloadfx.Reloadable)),
				fx.ResultTags(`group:"reloadables"`),
			),
		),
	)
}
