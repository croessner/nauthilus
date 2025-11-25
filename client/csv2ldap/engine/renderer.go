package engine

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
)

// TemplateRenderer replaces placeholders in a loaded LDIF template.
// Supported placeholders: {{ uuid4 }}, {{ localpart }}, {{ password }}
type TemplateRenderer struct {
	tpl string
	enc PasswordEncoder
}

// NewTemplateRenderer reads template file into memory and wires a PasswordEncoder.
func NewTemplateRenderer(templatePath string, enc PasswordEncoder) (*TemplateRenderer, error) {
	b, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	return &TemplateRenderer{tpl: string(b), enc: enc}, nil
}

// Render applies the template to the record with a fresh UUIDv4 per entry.
func (tr *TemplateRenderer) Render(r *Record) (string, error) {
	id, err := uuid4()
	if err != nil {
		return "", err
	}

	pw := r.Password
	if tr.enc != nil {
		encPw, err := tr.enc.Encode(r.Password)
		if err != nil {
			return "", err
		}
		pw = encPw
	}

	repl := strings.NewReplacer(
		"{{ uuid4 }}", id,
		"{{ localpart }}", r.Username,
		"{{ password }}", pw,
	)

	s := repl.Replace(tr.tpl)

	// Ensure a blank line after each entry for LDIF readability
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}

	if !strings.HasSuffix(s, "\n\n") {
		s += "\n"
	}

	return s, nil
}

// uuid4 generates RFC 4122 UUID v4 without external deps.
func uuid4() (string, error) {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
