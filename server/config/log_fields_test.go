package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-viper/mapstructure/v2"
)

// TestNoticeIgnoreFields validates the public configuration and required-field boundary.
func TestNoticeIgnoreFields(t *testing.T) {
	for _, test := range []struct {
		name    string
		keys    []string
		invalid bool
	}{
		{"unset", nil, false},
		{"empty", []string{}, false},
		{"custom", []string{"ldap_lookup", "rbl custom", "source", "user_agent"}, false},
		{"time", []string{"time"}, true},
		{"level", []string{"level"}, true},
		{"instance", []string{"instance"}, true},
		{"session", []string{"session"}, true},
		{"msg", []string{"msg"}, true},
		{"blank", []string{" "}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cfg FileSettings

			input := map[string]any{"observability": map[string]any{"log": map[string]any{"notice_ignore_fields": test.keys}}}
			if err := mapstructure.Decode(input, &cfg); err != nil {
				t.Fatal(err)
			}

			got := cfg.GetServer().GetLog().GetNoticeIgnoreFields()
			if !reflect.DeepEqual(got, test.keys) {
				t.Fatalf("keys = %#v, want %#v", got, test.keys)
			}

			if err := cfg.validateNoticeIgnoreFields(); (err != nil) != test.invalid {
				t.Fatalf("validation error = %v, invalid = %v", err, test.invalid)
			}
		})
	}
}

// TestNoticeIgnoreFieldsDefaultDump keeps the new setting discoverable in generated config.
func TestNoticeIgnoreFieldsDefaultDump(t *testing.T) {
	dump, err := RenderDefaultConfigDumpWithFormat(DumpFormatYAML)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(dump, "notice_ignore_fields:") {
		t.Fatal("default config dump omits notice_ignore_fields")
	}
}
