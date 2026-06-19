package auth

import (
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/util"
)

func init() {
	util.SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: true})
}
