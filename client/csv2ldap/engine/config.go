package engine

import "path/filepath"

// Config carries file paths, CSV column names and filter settings.
type Config struct {
	// Paths
	InCSVPath    string
	TemplatePath string
	OutLDIFPath  string

	// CSV column names
	ColUsername   string
	ColPassword   string
	ColProtocol   string
	ColExpectedOK string

	// Filter knobs
	ExpectTrueValue  string
	AllowedProtocols []string

	// Password formatting
	// PasswordFormat selects how {{ password }} is rendered into the LDIF entry.
	// Supported: "ssha256", "ssha512", "argon2i", "argon2id".
	PasswordFormat string
	// SSHAEncoding selects payload encoding: "b64" or "hex". Default: b64.
	SSHAEncoding string
	// Argon2 parameters (only used for argon2i/argon2id)
	ArgonTime        uint32 // iterations
	ArgonMemoryKiB   uint32 // memory in KiB
	ArgonParallelism uint8  // threads
	ArgonKeyLen      uint32 // length of derived key in bytes
	// If true, prepend {ARGON2} to the PHC string for OpenLDAP compatibility.
	ArgonOpenLDAPPrefix bool
}

// DefaultConfig provides sensible defaults rooted in ./client/* as requested.
func DefaultConfig() Config {
	return Config{
		InCSVPath:           filepath.FromSlash("client/logins.local.csv"),
		TemplatePath:        filepath.FromSlash("client/template.ldif"),
		OutLDIFPath:         filepath.FromSlash("client/result.ldif"),
		ColUsername:         "username",
		ColPassword:         "password",
		ColProtocol:         "protocol",
		ColExpectedOK:       "expected_ok",
		ExpectTrueValue:     "true",
		AllowedProtocols:    []string{"imap", "smtp"},
		PasswordFormat:      "ssha512",
		SSHAEncoding:        "b64",
		ArgonTime:           2,
		ArgonMemoryKiB:      65536,
		ArgonParallelism:    1,
		ArgonKeyLen:         32,
		ArgonOpenLDAPPrefix: true,
	}
}
