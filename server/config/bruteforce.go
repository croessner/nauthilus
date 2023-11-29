package config

// BruteForceRule is the definition of a brute force rule as defined in the configuration file. See the markdown
// documentation for a description of the field names.
type BruteForceRule struct {
	Name           string
	Period         uint
	CIDR           uint
	IPv4           bool
	IPv6           bool
	FailedRequests uint `mapstructure:"failed_requests"`
}
