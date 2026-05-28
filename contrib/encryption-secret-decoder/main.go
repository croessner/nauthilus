// Copyright (C) 2026 Christian Rößner
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

// Package main provides a Nauthilus encryption-secret decoder helper.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/security"
)

const (
	defaultSecretPrompt     = "encryption_secret: "
	defaultCiphertextPrompt = "encrypted value: "
)

var (
	errEmptyCiphertext = errors.New("encrypted value is required")
	errTooManyArgs     = errors.New("expected at most one encrypted value argument")
)

// options stores command line choices for the decoder helper.
type options struct {
	ciphertext     string
	ciphertextFile string
}

// main runs the decoder and turns user-facing errors into process exit codes.
func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)

		os.Exit(1)
	}
}

// run parses command line options, prompts for the secret, and writes decoded plaintext.
func run(args []string, stdin *os.File, stdout io.Writer, stderr io.Writer) error {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		return err
	}

	secretValue, err := readSecret(stderr)
	if err != nil {
		return err
	}
	defer clear(secretValue)

	ciphertext, err := readCiphertext(opts, stdin, stderr)
	if err != nil {
		return err
	}

	plaintext, err := decryptCiphertext(secretValue, ciphertext)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(stdout, printablePlaintext(plaintext))

	return err
}

// parseOptions collects the optional ciphertext sources accepted by the helper.
func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options

	fs := flag.NewFlagSet("encryption-secret-decoder", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.ciphertext, "ciphertext", "", "base64 encrypted value to decode")
	fs.StringVar(&opts.ciphertextFile, "ciphertext-file", "", "file containing the encrypted value")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: %s [options] [encrypted-value]\n", fs.Name())
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	if fs.NArg() > 1 {
		fs.Usage()

		return options{}, errTooManyArgs
	}

	if opts.ciphertext != "" && opts.ciphertextFile != "" {
		fs.Usage()

		return options{}, errors.New("-ciphertext and -ciphertext-file are mutually exclusive")
	}

	if fs.NArg() == 1 {
		if opts.ciphertext != "" || opts.ciphertextFile != "" {
			fs.Usage()

			return options{}, errors.New("positional encrypted value cannot be combined with ciphertext options")
		}

		opts.ciphertext = fs.Arg(0)
	}

	return opts, nil
}

// readSecret prompts for the encryption secret without echoing the raw value.
func readSecret(stderr io.Writer) ([]byte, error) {
	terminal, closeTerminal, err := openSecretTerminal(os.Stdin)
	if err != nil {
		return nil, err
	}

	if closeTerminal {
		defer func() {
			_ = terminal.Close()
		}()
	}

	return readMaskedLine(terminal, stderr, defaultSecretPrompt)
}

// readCiphertext reads the encrypted value from flags, a file, stdin, or an interactive prompt.
func readCiphertext(opts options, stdin *os.File, stderr io.Writer) (string, error) {
	switch {
	case opts.ciphertext != "":
		return cleanCiphertext(opts.ciphertext)
	case opts.ciphertextFile != "":
		return readCiphertextFile(opts.ciphertextFile)
	case stdin != nil && !isTerminal(stdin):
		return readCiphertextReader(stdin)
	default:
		return readCiphertextPrompt(stdin, stderr)
	}
}

// readCiphertextFile reads and trims an encrypted value from a file.
func readCiphertextFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return cleanCiphertext(string(content))
}

// readCiphertextReader reads and trims an encrypted value from a non-terminal stream.
func readCiphertextReader(reader io.Reader) (string, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}

	return cleanCiphertext(string(content))
}

// readCiphertextPrompt asks for the encrypted value when stdin is interactive.
func readCiphertextPrompt(stdin *os.File, stderr io.Writer) (string, error) {
	if stdin == nil {
		return "", errEmptyCiphertext
	}

	if _, err := fmt.Fprint(stderr, defaultCiphertextPrompt); err != nil {
		return "", err
	}

	content, err := readPlainLine(stdin)
	if err != nil {
		return "", err
	}

	return cleanCiphertext(string(content))
}

// cleanCiphertext trims surrounding whitespace and rejects empty encrypted values.
func cleanCiphertext(value string) (string, error) {
	ciphertext := strings.TrimSpace(value)
	if ciphertext == "" {
		return "", errEmptyCiphertext
	}

	return ciphertext, nil
}

// decryptCiphertext applies the same security manager path used for Redis and LDAP secrets.
func decryptCiphertext(secretBytes []byte, ciphertext string) (string, error) {
	manager := security.NewManager(secret.FromBytes(secretBytes))

	return manager.Decrypt(ciphertext)
}

// printablePlaintext returns a terminal-safe representation without emitting raw binary bytes.
func printablePlaintext(value string) string {
	if utf8.ValidString(value) {
		return printableUTF8(value)
	}

	return printableBytes([]byte(value))
}

// printableUTF8 escapes non-printing runes while preserving printable Unicode text.
func printableUTF8(value string) string {
	var builder strings.Builder

	for _, r := range value {
		appendEscapedRune(&builder, r)
	}

	return builder.String()
}

// printableBytes escapes invalid UTF-8 or binary plaintext byte by byte.
func printableBytes(value []byte) string {
	var builder strings.Builder

	for _, b := range value {
		appendEscapedByte(&builder, b)
	}

	return builder.String()
}

// appendEscapedRune writes one printable or escaped rune to the builder.
func appendEscapedRune(builder *strings.Builder, r rune) {
	switch r {
	case '\\':
		builder.WriteString(`\\`)
	case '\n':
		builder.WriteString(`\n`)
	case '\r':
		builder.WriteString(`\r`)
	case '\t':
		builder.WriteString(`\t`)
	default:
		appendPrintableRune(builder, r)
	}
}

// appendPrintableRune preserves visible runes and uses Go-style escapes otherwise.
func appendPrintableRune(builder *strings.Builder, r rune) {
	if unicode.IsPrint(r) {
		builder.WriteRune(r)

		return
	}

	if r <= 0xff {
		appendHexEscape(builder, `\x`, uint64(r), 2)

		return
	}

	if r <= 0xffff {
		appendHexEscape(builder, `\u`, uint64(r), 4)

		return
	}

	appendHexEscape(builder, `\U`, uint64(r), 8)
}

// appendEscapedByte writes one printable or escaped byte to the builder.
func appendEscapedByte(builder *strings.Builder, value byte) {
	switch value {
	case '\\':
		builder.WriteString(`\\`)
	case '\n':
		builder.WriteString(`\n`)
	case '\r':
		builder.WriteString(`\r`)
	case '\t':
		builder.WriteString(`\t`)
	default:
		appendPrintableByte(builder, value)
	}
}

// appendPrintableByte preserves visible ASCII bytes and hex-escapes everything else.
func appendPrintableByte(builder *strings.Builder, value byte) {
	if value >= 0x20 && value <= 0x7e {
		builder.WriteByte(value)

		return
	}

	appendHexEscape(builder, `\x`, uint64(value), 2)
}

// appendHexEscape writes a fixed-width lowercase hexadecimal escape sequence.
func appendHexEscape(builder *strings.Builder, prefix string, value uint64, width int) {
	const digits = "0123456789abcdef"

	builder.WriteString(prefix)

	for shift := (width - 1) * 4; shift >= 0; shift -= 4 {
		builder.WriteByte(digits[(value>>shift)&0xf])
	}
}
