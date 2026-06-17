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

// Command nauthilus-plugin-sign creates and signs native plugin distribution keys.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/croessner/nauthilus/server/pluginloader"
)

const (
	commandKeygen           = "keygen"
	commandPublicKey        = "public-key"
	commandSign             = "sign"
	defaultKeyComment       = "nauthilus plugin build key"
	defaultTrustedCommentID = "nauthilus-plugin-build"
)

// command owns process I/O for testable subcommand execution.
type command struct {
	stdout io.Writer
	stderr io.Writer
}

// main runs the signing command and maps usage failures to a non-zero exit code.
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "nauthilus-plugin-sign: %v\n", err)

		os.Exit(2)
	}
}

// run dispatches one signing subcommand.
func run(args []string, stdout io.Writer, stderr io.Writer) error {
	cmd := command{
		stdout: stdout,
		stderr: stderr,
	}

	if len(args) == 0 {
		cmd.printUsage()

		return fmt.Errorf("missing command")
	}

	switch args[0] {
	case commandKeygen:
		return cmd.runKeygen(args[1:])
	case commandPublicKey:
		return cmd.runPublicKey(args[1:])
	case commandSign:
		return cmd.runSign(args[1:])
	case "help", "-h", "--help":
		cmd.printUsage()

		return nil
	default:
		cmd.printUsage()

		return fmt.Errorf("unknown command %q", args[0])
	}
}

// runKeygen generates an Ed25519 seed and matching public key text.
func (c command) runKeygen(args []string) error {
	fs := c.newFlagSet(commandKeygen)

	comment := fs.String("comment", defaultKeyComment, "single-line public key comment")
	if err := fs.Parse(args); err != nil {
		return err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate plugin signing key: %w", err)
	}

	keyID, err := pluginloader.DefaultPluginSigningKeyID(publicKey)
	if err != nil {
		return err
	}

	publicKeyText, err := pluginloader.FormatPluginPublicKey(publicKey, keyID, *comment)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(c.stdout, "NAUTHILUS_PLUGIN_SIGNING_KEY_B64=%s\n", base64.StdEncoding.EncodeToString(privateKey.Seed()))
	_, _ = fmt.Fprintf(c.stdout, "NAUTHILUS_PLUGIN_SIGNING_KEY_ID=%s\n", hex.EncodeToString(keyID))
	_, _ = fmt.Fprintln(c.stdout, "Public key:")
	_, _ = c.stdout.Write(publicKeyText)

	return nil
}

// runPublicKey derives public key text from an existing base64 private key file.
func (c command) runPublicKey(args []string) error {
	fs := c.newFlagSet(commandPublicKey)

	privateKeyFile := fs.String("private-key-file", "", "file containing a base64 Ed25519 seed or private key")
	comment := fs.String("comment", defaultKeyComment, "single-line public key comment")

	if err := fs.Parse(args); err != nil {
		return err
	}

	privateKey, err := readPrivateKeyFile(*privateKeyFile)
	if err != nil {
		return err
	}

	publicKey, err := publicKeyFromPrivateKey(privateKey)
	if err != nil {
		return err
	}

	keyID, err := pluginloader.DefaultPluginSigningKeyID(publicKey)
	if err != nil {
		return err
	}

	publicKeyText, err := pluginloader.FormatPluginPublicKey(publicKey, keyID, *comment)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(c.stdout, "NAUTHILUS_PLUGIN_SIGNING_KEY_ID=%s\n", hex.EncodeToString(keyID))
	_, _ = c.stdout.Write(publicKeyText)

	return nil
}

// runSign writes a minisign-style detached signature for one plugin artifact.
func (c command) runSign(args []string) error {
	fs := c.newFlagSet(commandSign)
	artifact := fs.String("artifact", "", "plugin artifact path")
	signature := fs.String("signature", "", "signature output path")
	privateKeyFile := fs.String("private-key-file", "", "file containing a base64 Ed25519 seed or private key")
	trustedComment := fs.String("trusted-comment", "", "single-line minisign trusted comment")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *artifact == "" {
		return fmt.Errorf("--artifact is required")
	}

	signaturePath := *signature
	if signaturePath == "" {
		signaturePath = *artifact + ".minisig"
	}

	privateKey, err := readPrivateKeyFile(*privateKeyFile)
	if err != nil {
		return err
	}

	publicKey, err := publicKeyFromPrivateKey(privateKey)
	if err != nil {
		return err
	}

	keyID, err := pluginloader.DefaultPluginSigningKeyID(publicKey)
	if err != nil {
		return err
	}

	comment := *trustedComment
	if comment == "" {
		comment = defaultTrustedComment(*artifact)
	}

	if err := pluginloader.WriteMinisignSignatureFile(*artifact, signaturePath, privateKey, keyID, comment); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(c.stdout, "signed %s -> %s\n", *artifact, signaturePath)

	return nil
}

// newFlagSet returns a subcommand flag set with shared error output.
func (c command) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)

	return fs
}

// printUsage writes the top-level command usage.
func (c command) printUsage() {
	_, _ = fmt.Fprintln(c.stderr, "Usage: nauthilus-plugin-sign <keygen|public-key|sign> [options]")
}

// readPrivateKeyFile loads and parses build-time signing secret material.
func readPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("--private-key-file is required")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugin signing private key %q: %w", path, err)
	}

	privateKey, err := pluginloader.ParsePluginSigningPrivateKey(raw)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// publicKeyFromPrivateKey extracts the Ed25519 public key component.
func publicKeyFromPrivateKey(privateKey ed25519.PrivateKey) (ed25519.PublicKey, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("plugin signing private key does not expose an Ed25519 public key")
	}

	return publicKey, nil
}

// defaultTrustedComment returns the default minisign trusted comment for one artifact.
func defaultTrustedComment(artifact string) string {
	return fmt.Sprintf("timestamp:%d\tfile:%s\t%s\thashed", time.Now().Unix(), filepath.Base(artifact), defaultTrustedCommentID)
}
