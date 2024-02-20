package config

import (
	"time"
)

type ServerSection struct {
	Address             string      `mapstructure:"address"`
	TLS                 TLS         `mapstructure:"tls"`
	BasicAuth           BasicAuth   `mapstructure:"basic_auth"`
	InstanceName        string      `mapstructure:"instance_name"`
	Log                 Log         `maptostructure:"log"`
	Backends            []*Backend  `mapstructure:"backends"`
	Features            []*Feature  `mapstructure:"features"`
	BruteForceProtocols []*Protocol `mapstructure:"brute_force_protocols"`
	HydraAdminUrl       string      `mapstructure:"ory_hydra_admin_url"`
	DNS                 DNS         `mapstructure:"dns"`
	Insights            Insights    `mapstructure:"insights"`
}

type TLS struct {
	Enabled              bool   `mapstructure:"enabled"`
	Cert                 string `mapstructure:"cert"`
	Key                  string `mapstructure:"key"`
	HTTPClientSkipVerify bool   `mapstructure:"http_client_skip_verify"`
}

type BasicAuth struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type Log struct {
	JSON       bool         `mapstructure:"json"`
	Level      Verbosity    `mapstructure:"level"`
	DbgModules []*DbgModule `mapstructure:"debug_modules"`
}

type Insights struct {
	EnablePprof        bool `mapstructure:"enable_pprof"`
	EnableBlockProfile bool `mapstructure:"enable_block_profile"`
}

type DNS struct {
	Resolver        string        `mapstructure:"resolver"`
	Timeout         time.Duration `mapstructure:"timeout"`
	ResolveClientIP bool          `mapstructure:"resolve_client_ip"`
}
