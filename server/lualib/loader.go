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
	"context"
	stdhttp "net/http"

	"github.com/cjoudrey/gluahttp"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/metrics"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/lualib/smtp"
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

// RegisterCommonLuaLibraries preloads Lua libraries based on the given module name and updates the registry map.
func RegisterCommonLuaLibraries(L *lua.LState, ctx context.Context, modName string, registry map[string]bool, httpClient *stdhttp.Client) {
	switch modName {
	case definitions.LuaModGLLPlugin:
		plugin.Preload(L)
	case definitions.LuaModGLLArgParse:
		argparse.Preload(L)
	case definitions.LuaModGLLBase64:
		base64.Preload(L)
	case definitions.LuaModGLLCertUtil:
		cert_util.Preload(L)
	case definitions.LuaModGLLChef:
		chef.Preload(L)
	case definitions.LuaModGLLCloudWatch:
		cloudwatch.Preload(L)
	case definitions.LuaModGLLCmd:
		cmd.Preload(L)
	case definitions.LuaModGLLCrypto:
		crypto.Preload(L)
	case definitions.LuaModGLLDB:
		db.Preload(L)
	case definitions.LuaModGLLFilePath:
		filepath.Preload(L)
	case definitions.LuaModGLLGOOS:
		goos.Preload(L)
	case definitions.LuaModGLLHTTP:
		http.Preload(L)
	case definitions.LuaModGLLHumanize:
		humanize.Preload(L)
	case definitions.LuaModGLLInspect:
		inspect.Preload(L)
	case definitions.LuaModGLLIOUtil:
		ioutil.Preload(L)
	case definitions.LuaModGLLJSON:
		json.Preload(L)
	case definitions.LuaModGLLLog:
		log.Preload(L)
	case definitions.LuaModGLLPb:
		pb.Preload(L)
	case definitions.LuaModGLLPProf:
		pprof.Preload(L)
	case definitions.LuaModGLLPrometheus:
		prometheus.Preload(L)
	case definitions.LuaModGLLRegExp:
		regexp.Preload(L)
	case definitions.LuaModGLLRuntime:
		runtime.Preload(L)
	case definitions.LuaModGLLShellEscape:
		shellescape.Preload(L)
	case definitions.LuaModGLLStats:
		stats.Preload(L)
	case definitions.LuaModGLLStorage:
		storage.Preload(L)
	case definitions.LuaModGLLStrings:
		strings.Preload(L)
	case definitions.LuaModGLLTAC:
		tac.Preload(L)
	case definitions.LuaModGLLTCP:
		tcp.Preload(L)
	case definitions.LuaModGLLTelegram:
		telegram.Preload(L)
	case definitions.LuaModGLLTemplate:
		template.Preload(L)
	case definitions.LuaModGLLTime:
		time.Preload(L)
	case definitions.LuaModGLLXMLPath:
		xmlpath.Preload(L)
	case definitions.LuaModGLLYAML:
		yaml.Preload(L)
	case definitions.LuaModGLLZabbix:
		zabbix.Preload(L)
	case definitions.LuaModGLuaCrypto:
		gluacrypto.Preload(L)
	case definitions.LuaModGLuaHTTP:
		httpModule := gluahttp.NewHttpModule(httpClient)

		L.PreloadModule("glua_http", httpModule.Loader)
	case definitions.LuaModPassword:
		L.PreloadModule(modName, LoaderModPassword)
	case definitions.LuaModRedis:
		L.PreloadModule(modName, redislib.LoaderModRedis(ctx))
	case definitions.LuaModMail:
		smtpClient := &smtp.EmailClient{}
		mailModule := NewMailModule(smtpClient)

		L.PreloadModule(modName, mailModule.Loader)
	case definitions.LuaModMisc:
		L.PreloadModule(modName, LoaderModMisc)
	case definitions.LuaModPrometheus:
		L.PreloadModule(modName, metrics.LoaderModPrometheus)
	case definitions.LuaModPsnet:
		L.PreloadModule(modName, connmgr.LoaderModPsnet(ctx))
	case definitions.LuaModSoftWhitelist:
		L.PreloadModule(modName, LoaderModSoftWhitelist)
	case definitions.LuaModBruteForce:
		L.PreloadModule(modName, bruteforce.LoaderModBruteForce(ctx))
	default:
		return
	}

	registry[modName] = true

	return
}
