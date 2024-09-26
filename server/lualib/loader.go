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

package lualib

import (
	"crypto/tls"
	stdhttp "net/http"
	stdtime "time"

	"github.com/cjoudrey/gluahttp"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/tengattack/gluacrypto"
	"github.com/vadv/gopher-lua-libs/argparse"
	"github.com/vadv/gopher-lua-libs/aws/cloudwatch"
	"github.com/vadv/gopher-lua-libs/base64"
	"github.com/vadv/gopher-lua-libs/cert_util"
	"github.com/vadv/gopher-lua-libs/chef"
	"github.com/vadv/gopher-lua-libs/cmd"
	"github.com/vadv/gopher-lua-libs/crypto"
	"github.com/vadv/gopher-lua-libs/db"
	"github.com/vadv/gopher-lua-libs/filepath"
	"github.com/vadv/gopher-lua-libs/goos"
	"github.com/vadv/gopher-lua-libs/http"
	"github.com/vadv/gopher-lua-libs/humanize"
	"github.com/vadv/gopher-lua-libs/inspect"
	"github.com/vadv/gopher-lua-libs/ioutil"
	"github.com/vadv/gopher-lua-libs/json"
	"github.com/vadv/gopher-lua-libs/log"
	"github.com/vadv/gopher-lua-libs/pb"
	"github.com/vadv/gopher-lua-libs/plugin"
	"github.com/vadv/gopher-lua-libs/pprof"
	prometheus "github.com/vadv/gopher-lua-libs/prometheus/client"
	"github.com/vadv/gopher-lua-libs/regexp"
	"github.com/vadv/gopher-lua-libs/runtime"
	"github.com/vadv/gopher-lua-libs/shellescape"
	"github.com/vadv/gopher-lua-libs/stats"
	"github.com/vadv/gopher-lua-libs/storage"
	"github.com/vadv/gopher-lua-libs/strings"
	"github.com/vadv/gopher-lua-libs/tac"
	"github.com/vadv/gopher-lua-libs/tcp"
	"github.com/vadv/gopher-lua-libs/telegram"
	"github.com/vadv/gopher-lua-libs/template"
	"github.com/vadv/gopher-lua-libs/time"
	"github.com/vadv/gopher-lua-libs/xmlpath"
	"github.com/vadv/gopher-lua-libs/yaml"
	"github.com/vadv/gopher-lua-libs/zabbix"
	lua "github.com/yuin/gopher-lua"
)

// RegisterCommonLuaLibraries registers common Lua libraries based on the modName value.
// The function takes an *lua.Lstate, modName string, and registry map[string]bool as input parameters.
// It uses a switch statement to compare modName with pre-defined constants to determine which library to register.
// For each matched modName, it calls the corresponding Preload function to register the library.
// After registering the library, it adds the modName to the registry map to keep track of registered libraries.
// If modName does not match any pre-defined constants, the function returns without registering any library.
//
// Note: The implementation of Preload functions for each library is not shown in this documentation.
// Please refer to the individual module documentations for more details on each Preload function.
// Please also note that the declaration codes for the constants used in the switch cases are not shown here.
// Refer to the module documentations for the declaration codes of the constants.
func RegisterCommonLuaLibraries(L *lua.LState, modName string, registry map[string]bool) {
	switch modName {
	case global.LuaModGLLPlugin:
		plugin.Preload(L)
	case global.LuaModGLLArgParse:
		argparse.Preload(L)
	case global.LuaModGLLBase64:
		base64.Preload(L)
	case global.LuaModGLLCertUtil:
		cert_util.Preload(L)
	case global.LuaModGLLChef:
		chef.Preload(L)
	case global.LuaModGLLCloudWatch:
		cloudwatch.Preload(L)
	case global.LuaModGLLCmd:
		cmd.Preload(L)
	case global.LuaModGLLCrypto:
		crypto.Preload(L)
	case global.LuaModGLLDB:
		db.Preload(L)
	case global.LuaModGLLFilePath:
		filepath.Preload(L)
	case global.LuaModGLLGOOS:
		goos.Preload(L)
	case global.LuaModGLLHTTP:
		http.Preload(L)
	case global.LuaModGLLHumanize:
		humanize.Preload(L)
	case global.LuaModGLLInspect:
		inspect.Preload(L)
	case global.LuaModGLLIOUtil:
		ioutil.Preload(L)
	case global.LuaModGLLJSON:
		json.Preload(L)
	case global.LuaModGLLLog:
		log.Preload(L)
	case global.LuaModGLLPb:
		pb.Preload(L)
	case global.LuaModGLLPProf:
		pprof.Preload(L)
	case global.LuaModGLLPrometheus:
		prometheus.Preload(L)
	case global.LuaModGLLRegExp:
		regexp.Preload(L)
	case global.LuaModGLLRuntime:
		runtime.Preload(L)
	case global.LuaModGLLShellEscape:
		shellescape.Preload(L)
	case global.LuaModGLLStats:
		stats.Preload(L)
	case global.LuaModGLLStorage:
		storage.Preload(L)
	case global.LuaModGLLStrings:
		strings.Preload(L)
	case global.LuaModGLLTAC:
		tac.Preload(L)
	case global.LuaModGLLTCP:
		tcp.Preload(L)
	case global.LuaModGLLTelegram:
		telegram.Preload(L)
	case global.LuaModGLLTemplate:
		template.Preload(L)
	case global.LuaModGLLTime:
		time.Preload(L)
	case global.LuaModGLLXMLPath:
		xmlpath.Preload(L)
	case global.LuaModGLLYAML:
		yaml.Preload(L)
	case global.LuaModGLLZabbix:
		zabbix.Preload(L)
	case global.LuaModGLuaCrypto:
		gluacrypto.Preload(L)
	case global.LuaModGLuaHTTP:
		httpClient := &stdhttp.Client{
			Timeout: 60 * stdtime.Second,
			Transport: &stdhttp.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: config.LoadableConfig.Server.TLS.HTTPClientSkipVerify,
				},
			},
		}

		L.PreloadModule("glua_http", gluahttp.NewHttpModule(httpClient).Loader)
	case global.LuaModPassword:
		L.PreloadModule(modName, LoaderModPassword)
	case global.LuaModRedis:
		L.PreloadModule(modName, redislib.LoaderModRedis)
	case global.LuaModMail:
		L.PreloadModule(modName, LoaderModMail)
	case global.LuaModMisc:
		L.PreloadModule(modName, LoaderModMisc)
	default:
		return
	}

	registry[modName] = true
}
