package adminui

import (
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/util"
)

func init() {
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())
}
