package engine

// Row represents a single data entry for a request.
type Row struct {
	Username  string
	Password  string
	IP        string
	ExpectOK  bool
	RawFields map[string]string

	BadPass bool
	NoAuth  bool
}

// RowSource is an interface for providing rows of data.
type RowSource interface {
	Next() (Row, bool)
	Reset()
	Total() int
}
