package config

import "fmt"

type RelayDomainsSection struct {
	StaticDomains []string `mapstructure:"static"`
}

func (r *RelayDomainsSection) String() string {
	return fmt.Sprintf("RelayDomainsSection: {Static[%+v]}", r.StaticDomains)
}

type BackendServer struct {
	Protocol  string `mapstructure:"protocol"`
	IP        string `mapstructure:"ip"`
	Port      int    `mapstructure:"port"`
	TLS       bool   `mapstructure:"tls"`
	HAProxyV2 bool   `mapstructure:"haproxy_v2"`
}

func (n *BackendServer) String() string {
	return fmt.Sprintf("BackendServers: {Protocol: %s, IP: %s, Port: %d}", n.Protocol, n.IP, n.Port)
}

type BackendServerMonitoring struct {
	BackendServers []*BackendServer `mapstructure:"backend_servers"`
}

func (n *BackendServerMonitoring) string() string {
	return fmt.Sprintf("BackendServerMonitoring: [%v]", n.BackendServers)
}
