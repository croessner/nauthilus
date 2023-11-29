package config

type RBL struct {
	Name         string
	RBL          string
	IPv4         bool
	IPv6         bool
	AllowFailure bool   `mapstructure:"allow_failure"`
	ReturnCode   string `mapstructure:"return_code"`
	Weight       int
}
