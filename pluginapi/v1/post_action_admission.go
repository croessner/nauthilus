package pluginapi

import "errors"

// PostActionAdmissionLimits bounds callback admission within one host runtime generation.
type PostActionAdmissionLimits struct {
	RequestsPerSecond int
	MaxConcurrency    int
}

// Validate rejects unbounded or excessive optional callback limits.
func (l PostActionAdmissionLimits) Validate() error {
	if l.RequestsPerSecond < 1 || l.RequestsPerSecond > 10000 || l.MaxConcurrency < 1 || l.MaxConcurrency > 1024 {
		return errors.New("invalid post-action admission limits")
	}

	return nil
}

// BoundedPostActionTarget declares limits captured once at registration and enforced by the host.
// The rate uses a token bucket whose burst equals requestsPerSecond; concurrency bounds active callbacks.
type BoundedPostActionTarget interface {
	PostActionTarget
	AdmissionLimits() (requestsPerSecond, maxConcurrency int)
}
