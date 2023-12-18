package config

import "fmt"

type RelayDomainsSection struct {
	StaticDomains []string `mapstructure:"static"`
}

func (r *RelayDomainsSection) String() string {
	return fmt.Sprintf("RelayDomainsSection: {Static[%+v]}", r.StaticDomains)
}
