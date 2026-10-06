package log

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// noticeFieldFilter owns the immutable set of optional NOTICE fields to omit.
type noticeFieldFilter struct {
	ignored map[string]struct{}
}

// newNoticeFieldFilter copies configured keys and defensively preserves required fields.
func newNoticeFieldFilter(keys []string) *noticeFieldFilter {
	filter := &noticeFieldFilter{ignored: make(map[string]struct{}, len(keys))}

	for _, key := range keys {
		if !definitions.IsRequiredNoticeLogKey(key) {
			filter.ignored[key] = struct{}{}
		}
	}

	return filter
}

// replaceAttr drops matching attribute keys while retaining the NOTICE level name.
func (f *noticeFieldFilter) replaceAttr(_ []string, attr slog.Attr) slog.Attr {
	if _, ignored := f.ignored[attr.Key]; ignored {
		return slog.Attr{}
	}

	return noticeLevelReplaceAttr(nil, attr)
}

// noticeFieldHandler keeps filtering specific to NOTICE, including pre-bound fields.
type noticeFieldHandler struct {
	normal slog.Handler
	notice slog.Handler
}

// Enabled delegates the shared verbosity decision to the unfiltered handler.
func (h *noticeFieldHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.normal.Enabled(ctx, level)
}

// Handle selects the filtered encoder only for the exact NOTICE level.
func (h *noticeFieldHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level == slog.LevelInfo+definitions.SlogNoticeLevelOffset {
		return h.notice.Handle(ctx, record)
	}

	return h.normal.Handle(ctx, record)
}

// WithAttrs preserves independent encoded attributes for both level paths.
func (h *noticeFieldHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &noticeFieldHandler{normal: h.normal.WithAttrs(attrs), notice: h.notice.WithAttrs(attrs)}
}

// WithGroup preserves identical grouping for both level paths.
func (h *noticeFieldHandler) WithGroup(name string) slog.Handler {
	return &noticeFieldHandler{normal: h.normal.WithGroup(name), notice: h.notice.WithGroup(name)}
}
