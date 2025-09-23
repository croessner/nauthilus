package zstdmw

import (
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

// Level represents abstract compression levels similar to gzip middleware.
// They are mapped to klauspost/compress zstd encoder options.
type Level int

const (
	DefaultCompression Level = iota
	BestSpeed
	BetterCompression // reasonable ratio with good speed
	BestCompression   // maximum compression, slower
)

// ZstdEncoder is the minimal interface implemented by a Zstandard encoder used by this package.
// It is deliberately small to allow plugging in fakes/mocks in tests and to decouple from the concrete klauspost/compress implementation.
type ZstdEncoder interface {
	Write(p []byte) (int, error)
	Close() error
}

// encoderFactory abstracts encoder creation. It can be overridden in tests.
type encoderFactory func(w io.Writer, lvl Level) (ZstdEncoder, error)

// newEncoder is the package-level factory used to create encoders. In production it uses klauspost/compress/zstd.
var newEncoder encoderFactory = func(w io.Writer, lvl Level) (ZstdEncoder, error) {
	return zstd.NewWriter(w, encoderOptionsForLevel(lvl)...)
}

type config struct {
	level       Level
	minLength   int
	skipper     func(*gin.Context) bool
	excludeExt  map[string]struct{}
	excludePath map[string]struct{}
}

// Options defines a fluent builder interface for configuring the zstd middleware.
// Use NewOptions() to construct an instance and pass it to ZstdWith.
type Options interface {
	// WithMinLength sets the minimum content length (in bytes) for compression and returns the updated Options instance.
	WithMinLength(n int) Options

	// WithSkipper sets a custom function to determine whether a request should skip compression and returns the updated Options.
	WithSkipper(f func(*gin.Context) bool) Options

	// WithExcludeExtensions adds specified file extensions to the exclusion list, skipping compression for matching requests.
	WithExcludeExtensions(exts ...string) Options

	// WithExcludePaths adds the specified paths to the exclusion list, skipping compression for requests matching these paths.
	WithExcludePaths(paths ...string) Options

	// apply transfers the configured values to the internal config.
	// This is internal to the package; external implementations are not supported.
	apply(*config)
}

type optionsImpl struct {
	cfg *config
}

// NewOptions creates a new options builder.
func NewOptions() Options { return &optionsImpl{cfg: &config{}} }

// WithMinLength sets the minimum content length (in bytes) for compression and returns the updated Options instance.
func (o *optionsImpl) WithMinLength(n int) Options {
	o.cfg.minLength = n

	return o
}

// WithSkipper sets a custom function to determine if a request should bypass compression and returns the updated Options.
func (o *optionsImpl) WithSkipper(f func(*gin.Context) bool) Options {
	o.cfg.skipper = f

	return o
}

// WithExcludeExtensions adds specified file extensions to the exclusion list, skipping compression for matching requests.
func (o *optionsImpl) WithExcludeExtensions(exts ...string) Options {
	if o.cfg.excludeExt == nil {
		o.cfg.excludeExt = make(map[string]struct{})
	}

	for _, e := range exts {
		o.cfg.excludeExt[strings.ToLower(e)] = struct{}{}
	}

	return o
}

// WithExcludePaths adds the specified paths to the exclusion list, skipping compression for requests matching these paths.
func (o *optionsImpl) WithExcludePaths(paths ...string) Options {
	if o.cfg.excludePath == nil {
		o.cfg.excludePath = make(map[string]struct{})
	}

	for _, p := range paths {
		o.cfg.excludePath[p] = struct{}{}
	}

	return o
}

// apply copies configuration options from the optionsImpl instance to the destination config instance.
// It transfers scalar fields and ensures entries in maps are copied individually to avoid shared references.
func (o *optionsImpl) apply(dst *config) {
	// Merge fields into destination config. Maps are copied by entry.
	dst.minLength = o.cfg.minLength
	dst.skipper = o.cfg.skipper

	if len(o.cfg.excludeExt) > 0 {
		if dst.excludeExt == nil {
			dst.excludeExt = make(map[string]struct{}, len(o.cfg.excludeExt))
		}

		for k, v := range o.cfg.excludeExt {
			_ = v
			dst.excludeExt[k] = struct{}{}
		}
	}

	if len(o.cfg.excludePath) > 0 {
		if dst.excludePath == nil {
			dst.excludePath = make(map[string]struct{}, len(o.cfg.excludePath))
		}

		for k, v := range o.cfg.excludePath {
			_ = v
			dst.excludePath[k] = struct{}{}
		}
	}
}

// ZstdWith returns the middleware configured with the fluent Options builder.
func ZstdWith(level Level, o Options) gin.HandlerFunc {
	cfg := &config{level: level}
	if o != nil {
		o.apply(cfg)
	}

	return zstdHandler(cfg)
}

// Zstd provides a backward-compatible constructor using default options.
// It returns a middleware that applies Zstandard response compression when clients advertise support.
func Zstd(level Level) gin.HandlerFunc {
	return ZstdWith(level, nil)
}

// zstdHandler is a middleware function for Gin that applies Zstandard compression to HTTP responses, based on configuration.
func zstdHandler(cfg *config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.skipper != nil && cfg.skipper(c) {
			c.Next()

			return
		}

		if !acceptsZstd(c.Request) {
			c.Next()
			return
		}

		// Do not double-encode if already set.
		if hasContentEncoding(c.Writer.Header()) {
			c.Next()

			return
		}

		// Exclude exact path
		if _, ok := cfg.excludePath[c.Request.URL.Path]; ok {
			c.Next()

			return
		}
		// Exclude by extension
		if i := strings.LastIndexByte(c.Request.URL.Path, '.'); i >= 0 {
			ext := strings.ToLower(c.Request.URL.Path[i:])
			if _, ok := cfg.excludeExt[ext]; ok {
				c.Next()

				return
			}
		}

		w := &zstdResponseWriter{ResponseWriter: c.Writer, cfg: cfg, status: http.StatusOK}
		c.Writer = w

		c.Next()

		w.finish()
	}
}

// acceptsZstd checks if the request's "Accept-Encoding" header includes support for Zstandard compression.
func acceptsZstd(r *http.Request) bool {
	enc := r.Header.Get("Accept-Encoding")

	return strings.Contains(enc, "zstd") || strings.Contains(enc, "zst") || strings.Contains(enc, "zstandard")
}

// hasContentEncoding checks if the provided http.Header contains a non-empty "Content-Encoding" header.
func hasContentEncoding(h http.Header) bool {
	return h.Get("Content-Encoding") != ""
}

type zstdResponseWriter struct {
	gin.ResponseWriter
	cfg     *config
	status  int
	started bool
	enc     ZstdEncoder
}

// WriteHeader sets the status code for the response and ensures compression initialization if applicable.
func (w *zstdResponseWriter) WriteHeader(code int) {
	w.status = code
	w.start()
	w.ResponseWriter.WriteHeader(code)
}

// Write writes the input byte slice to the response, leveraging Zstandard encoding if initialized, or direct writing otherwise.
func (w *zstdResponseWriter) Write(b []byte) (int, error) {
	w.start()
	if w.enc == nil {
		return w.ResponseWriter.Write(b)
	}
	return w.enc.Write(b)
}

// start initializes the compression process if it hasn't started and adjusts headers appropriately for Zstandard encoding.
func (w *zstdResponseWriter) start() {
	if w.started {
		return
	}
	w.started = true

	// Skip compression for statuses with no body.
	if w.status < 200 || w.status == http.StatusNoContent || w.status == http.StatusNotModified {
		return
	}

	// Adjust headers for compressed output.
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", "zstd")
	vary := h.Get("Vary")
	if vary == "" {
		h.Set("Vary", "Accept-Encoding")
	} else if !strings.Contains(vary, "Accept-Encoding") {
		h.Set("Vary", vary+", Accept-Encoding")
	}

	// Create encoder with selected options via factory.
	enc, _ := newEncoder(w.ResponseWriter, w.cfg.level)
	w.enc = enc
}

// finish ensures the ZstdEncoder, if in use, is properly closed to release resources and complete the compression process.
func (w *zstdResponseWriter) finish() {
	if w.enc != nil {
		_ = w.enc.Close()
	}
}

// Flush checks if the underlying ResponseWriter supports the http.Flusher interface and calls its Flush method if available.
func (w *zstdResponseWriter) Flush() {
	if fl, ok := w.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// encoderOptionsForLevel returns a slice of zstd.EOption configured based on the provided compression Level.
func encoderOptionsForLevel(lvl Level) []zstd.EOption {
	switch lvl {
	case BestSpeed:
		return []zstd.EOption{zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithZeroFrames(true)}
	case BetterCompression:
		return []zstd.EOption{zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithWindowSize(1 << 20)}
	case BestCompression:
		return []zstd.EOption{zstd.WithEncoderLevel(zstd.SpeedBetterCompression)}
	case DefaultCompression:
		fallthrough
	default:
		return []zstd.EOption{zstd.WithEncoderLevel(zstd.SpeedDefault)}
	}
}
