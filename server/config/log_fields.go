package config

import (
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// validateNoticeIgnoreFields rejects protected and blank keys without restricting custom fields.
func (f *FileSettings) validateNoticeIgnoreFields() error {
	for _, key := range f.GetServer().GetLog().GetNoticeIgnoreFields() {
		if strings.TrimSpace(key) == "" || definitions.IsRequiredNoticeLogKey(key) {
			return fmt.Errorf("observability.log.notice_ignore_fields: field %q is empty or required", key)
		}
	}

	return nil
}
