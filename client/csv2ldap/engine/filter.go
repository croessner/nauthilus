package engine

import "strings"

// AllowOKProtocols filters for ExpectedOK==true and allowed protocols.
type AllowOKProtocols struct {
	allowed map[string]struct{}
}

// NewAllowOKProtocols constructs a filter for the provided protocols.
func NewAllowOKProtocols(protocols []string) *AllowOKProtocols {
	m := make(map[string]struct{}, len(protocols))
	for _, p := range protocols {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			m[p] = struct{}{}
		}
	}

	return &AllowOKProtocols{allowed: m}
}

// Allow accepts only records that are expected OK and protocol is in allowed set.
func (f *AllowOKProtocols) Allow(r *Record) bool {
	if r == nil || !r.ExpectedOK {
		return false
	}

	_, ok := f.allowed[strings.ToLower(strings.TrimSpace(r.Protocol))]

	return ok
}
