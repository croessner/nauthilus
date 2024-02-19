package config

type ServerSection struct {
	Log      `maptostructure:"log"`
	Insights `mapstructure:"insights"`
}

type Log struct {
	Level Verbosity `mapstructure:"level"`
}

type Insights struct {
	EnablePprof        bool `mapstructure:"enable_pprof"`
	EnableBlockProfile bool `mapstructure:"enable_block_profile"`
}
