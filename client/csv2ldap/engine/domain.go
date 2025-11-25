package engine

// Record represents one logical login record parsed from CSV.
type Record struct {
	Username   string
	Password   string
	Protocol   string
	ExpectedOK bool
}

// RecordSource yields records sequentially and must be closed when done.
type RecordSource interface {
	Next() (*Record, error) // returns io.EOF when exhausted
	Close() error
}

// RecordFilter decides whether a record should be processed.
type RecordFilter interface {
	Allow(r *Record) bool
}

// Renderer produces an LDIF entry text for a record.
type Renderer interface {
	Render(r *Record) (string, error)
}

// Sink consumes rendered entries.
type Sink interface {
	WriteEntry(entry string) error
	Close() error
}
