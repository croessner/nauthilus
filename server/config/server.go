package config

import "time"

type ServerSection struct {
	InstanceName        string      `mapstructure:"instance_name"`
	Log                 Log         `maptostructure:"log"`
	Insights            Insights    `mapstructure:"insights"`
	Features            []*Feature  `mapstructure:"features"`
	BruteForceProtocols []*Protocol `mapstructure:"brute_force_protocols"`
	DNS                 DNS         `mapstructure:"dns"`
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
