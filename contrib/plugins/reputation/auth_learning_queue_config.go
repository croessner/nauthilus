package main

import "time"

// authLearningQueueConfig bounds volatile learning independently of the scoring model.
type authLearningQueueConfig struct {
	MaxAge   string `mapstructure:"max_age"`
	Timeout  string `mapstructure:"timeout"`
	Capacity int    `mapstructure:"capacity"`
}

type learningQueueSettings struct {
	maxAge   time.Duration
	timeout  time.Duration
	capacity int
}

// settings resolves operational defaults without changing fingerprinted authentication semantics.
func (c authLearningQueueConfig) settings() (learningQueueSettings, error) {
	s := learningQueueSettings{capacity: c.Capacity, maxAge: 30 * time.Second, timeout: 5 * time.Second}
	if s.capacity == 0 {
		s.capacity = 1024
	}

	for _, field := range []struct {
		raw    string
		target *time.Duration
	}{{c.MaxAge, &s.maxAge}, {c.Timeout, &s.timeout}} {
		if field.raw == "" {
			continue
		}

		value, err := time.ParseDuration(field.raw)
		if err != nil {
			return s, errConfiguration
		}

		*field.target = value
	}

	if s.capacity < 1 || s.capacity > 65536 || s.maxAge <= 0 || s.maxAge > 5*time.Minute || s.timeout <= 0 || s.timeout > s.maxAge {
		return s, errConfiguration
	}

	return s, nil
}
