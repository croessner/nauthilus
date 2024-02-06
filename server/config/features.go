package config

import "fmt"

type RelayDomainsSection struct {
	StaticDomains []string `mapstructure:"static"`
}

func (r *RelayDomainsSection) String() string {
	return fmt.Sprintf("RelayDomainsSection: {Static[%+v]}", r.StaticDomains)
}

type NginxBackendServer struct {
	Protocol string
	IP       string
	Port     int
}

func (n *NginxBackendServer) String() string {
	return fmt.Sprintf("NginxBackendServer: {Protocol: %s, IP: %s, Port: %d}", n.Protocol, n.IP, n.Port)
}

type NginxMonitoring struct {
	NginxBackendServer []*NginxBackendServer `mapstructure:"backend_servers"`
}

func (n *NginxMonitoring) string() string {
	return fmt.Sprintf("NginxMonitoring: [%v]", n.NginxBackendServer)
}
