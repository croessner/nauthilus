package bruteforce

import (
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/util"
)

func init() {
	util.SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: true})
}
