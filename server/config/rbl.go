package config

import "fmt"

type RBLSection struct {
	Lists       []RBL
	Threshold   int
	IPWhiteList []string `mapstructure:"ip_whitelist"`
}

func (r *RBLSection) String() string {
	return fmt.Sprintf("RBLSection: {Lists[%+v] Threshold[%+v] Whitelist[%+v]}", r.Lists, r.Threshold, r.IPWhiteList)
}

type RBL struct {
	Name         string
	RBL          string
	IPv4         bool
	IPv6         bool
	AllowFailure bool   `mapstructure:"allow_failure"`
	ReturnCode   string `mapstructure:"return_code"`
	Weight       int
}
