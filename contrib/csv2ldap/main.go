// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package main provides the csv2ldap command.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/croessner/nauthilus/v3/contrib/csv2ldap/engine"
)

func main() {
	cfg := engine.DefaultConfig()
	flags := newCSV2LDAPFlags(cfg)

	flag.Parse()
	flags.apply(&cfg)

	app, err := newCSV2LDAPApp(cfg, flags.sshaSaltLength())
	fatalIf(err)

	n, err := app.Run()
	fatalIf(err)

	fmt.Printf("done. wrote %d entries to %s\n", n, cfg.OutLDIFPath)
}

type csv2LDAPFlags struct {
	in          *string
	template    *string
	out         *string
	expectField *string
	expectTrue  *string
	protocols   *string
	pwFormat    *string
	pwEncoding  *string
	pwSalt      *int
	argonT      *uint
	argonM      *uint
	argonP      *uint
	argonL      *uint
	argonPrefix *bool
}

// newCSV2LDAPFlags registers command-line flags and keeps their pointers.
func newCSV2LDAPFlags(cfg engine.Config) csv2LDAPFlags {
	return csv2LDAPFlags{
		in:          flag.String("in", cfg.InCSVPath, "Input CSV path"),
		template:    flag.String("template", cfg.TemplatePath, "LDIF template path"),
		out:         flag.String("out", cfg.OutLDIFPath, "LDIF output path"),
		expectField: flag.String("expect-field", cfg.ColExpectedOK, "CSV column used for expectation field"),
		expectTrue:  flag.String("expect-true", cfg.ExpectTrueValue, "CSV value considered as true (case-insensitive)"),
		protocols:   flag.String("protocols", strings.Join(cfg.AllowedProtocols, ","), "Allowed protocols (comma-separated)"),
		pwFormat:    flag.String("pw-format", cfg.PasswordFormat, "Password format: sha|ssha256|ssha512|argon2i|argon2id (default ssha512)"),
		pwEncoding:  flag.String("pw-ssha-encoding", cfg.SSHAEncoding, "SSHA payload encoding: b64|hex (default b64)"),
		pwSalt:      flag.Int("pw-ssha-salt", 8, "SSHA salt length in bytes"),
		argonT:      flag.Uint("argon-t", uint(cfg.ArgonTime), "Argon2 iterations (t)"),
		argonM:      flag.Uint("argon-m", uint(cfg.ArgonMemoryKiB), "Argon2 memory in KiB (m)"),
		argonP:      flag.Uint("argon-p", uint(cfg.ArgonParallelism), "Argon2 parallelism (p)"),
		argonL:      flag.Uint("argon-l", uint(cfg.ArgonKeyLen), "Argon2 hash length in bytes"),
		argonPrefix: flag.Bool("argon-prefix", cfg.ArgonOpenLDAPPrefix, "Prepend {ARGON2} to PHC string for OpenLDAP"),
	}
}

// apply copies parsed flag values into the engine config.
func (f csv2LDAPFlags) apply(cfg *engine.Config) {
	cfg.InCSVPath = *f.in
	cfg.TemplatePath = *f.template
	cfg.OutLDIFPath = *f.out
	cfg.ColExpectedOK = *f.expectField
	cfg.ExpectTrueValue = *f.expectTrue
	cfg.AllowedProtocols = splitCSV(*f.protocols)
	cfg.PasswordFormat = *f.pwFormat
	cfg.SSHAEncoding = *f.pwEncoding
	cfg.ArgonTime = uint32(*f.argonT)
	cfg.ArgonMemoryKiB = uint32(*f.argonM)
	cfg.ArgonParallelism = uint8(*f.argonP)
	cfg.ArgonKeyLen = uint32(*f.argonL)
	cfg.ArgonOpenLDAPPrefix = *f.argonPrefix
}

// sshaSaltLength returns the parsed SSHA salt length.
func (f csv2LDAPFlags) sshaSaltLength() int {
	return *f.pwSalt
}

// newCSV2LDAPApp composes the CSV source, filter, renderer, and LDIF sink.
func newCSV2LDAPApp(cfg engine.Config, saltLength int) (*engine.App, error) {
	src, err := engine.NewCSVSource(cfg)
	if err != nil {
		return nil, err
	}

	enc, err := newPasswordEncoder(cfg, saltLength)
	if err != nil {
		return nil, err
	}

	renderer, err := engine.NewTemplateRenderer(cfg.TemplatePath, enc)
	if err != nil {
		return nil, err
	}

	sink, err := engine.NewLDIFFileSink(cfg.OutLDIFPath)
	if err != nil {
		return nil, err
	}

	return &engine.App{
		Source: src,
		Filter: engine.NewAllowOKProtocols(cfg.AllowedProtocols),
		Render: renderer,
		Sink:   sink,
	}, nil
}

// newPasswordEncoder selects the configured password encoder.
func newPasswordEncoder(cfg engine.Config, saltLength int) (engine.PasswordEncoder, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.PasswordFormat)) {
	case "sha", "sha1":
		return &engine.SHAEncoder{Encoding: cfg.SSHAEncoding}, nil
	case "", "ssha512", "ssha256":
		return &engine.SSHAEncoder{Alg: cfg.PasswordFormat, Encoding: cfg.SSHAEncoding, SaltLength: saltLength}, nil
	case "argon2i":
		return newArgon2Encoder(cfg, engine.Argon2i), nil
	case "argon2id":
		return newArgon2Encoder(cfg, engine.Argon2id), nil
	default:
		return nil, fmt.Errorf("unsupported password format: %s", cfg.PasswordFormat)
	}
}

// newArgon2Encoder creates an Argon2 password encoder from config.
func newArgon2Encoder(cfg engine.Config, variant engine.Argon2Variant) *engine.Argon2Encoder {
	return &engine.Argon2Encoder{
		Variant:        variant,
		Time:           cfg.ArgonTime,
		MemoryKiB:      cfg.ArgonMemoryKiB,
		Parallelism:    cfg.ArgonParallelism,
		KeyLen:         cfg.ArgonKeyLen,
		OpenLDAPPrefix: cfg.ArgonOpenLDAPPrefix,
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}

func fatalIf(err error) {
	if err != nil {
		// Print a user-friendly error and exit non-zero
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)

		os.Exit(1)
	}
}
