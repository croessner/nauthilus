package config

type ServerSection struct {
	Insights `mapstructure:"insights"`
}

type Insights struct {
	EnablePprof        bool `mapstructure:"enable_pprof"`
	EnableBlockProfile bool `mapstructure:"enable_block_profile"`
}
