package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	jsoniter "github.com/json-iterator/go"
	"github.com/mattn/go-isatty"
	"github.com/mattn/go-runewidth"
	"golang.org/x/sys/unix"
)

// ANSI color helpers and styles for optional colored output in the client.
// These helpers are no-ops when colors are disabled.
const (
	ansiReset = "\x1b[0m"
	ansiDim   = "\x1b[2m"
	ansiBold  = "\x1b[1m"

	// Use bright ANSI colors to ensure good contrast on dark terminals
	// 90–97 are the bright variants of 30–37
	fgRed     = "\x1b[91m"
	fgGreen   = "\x1b[92m"
	fgYellow  = "\x1b[93m"
	fgBlue    = "\x1b[94m"
	fgMagenta = "\x1b[95m"
	fgCyan    = "\x1b[96m"
	fgWhite   = "\x1b[97m"
)

type colorStyle struct{ open, close string }

func style(enabled bool, open string) colorStyle {
	if !enabled {
		return colorStyle{"", ""}
	}

	return colorStyle{open: open, close: ansiReset}
}

func (cs colorStyle) S(s string) string { return cs.open + s + cs.close }

var (
	stOK    colorStyle
	stWarn  colorStyle
	stCrit  colorStyle
	stInfo  colorStyle
	stPlate colorStyle
	stDim   colorStyle
	stBold  colorStyle
	// stAxis colors axis glyphs in histograms and similar charts.
	stAxis colorStyle
)

func initColorStyles(enabled bool) {
	stOK = style(enabled, fgGreen)
	stWarn = style(enabled, fgYellow)
	stCrit = style(enabled, fgRed)
	stInfo = style(enabled, fgCyan)
	stPlate = style(enabled, fgMagenta)
	stDim = style(enabled, ansiDim)
	stBold = style(enabled, ansiBold)
	stAxis = style(enabled, fgBlue)
}

// Global indicator for plateau status to influence UI coloring.
var plateauActive int32 // 0 = no, 1 = yes

// supportsUnicode attempts to detect if the terminal likely supports UTF-8.
// If not, the client will fall back to pure ASCII characters for the progress bar
// to avoid mojibake (e.g., "���").
func supportsUnicode() bool {
	// Prefer LC_ALL, then LC_CTYPE, then LANG
	if v := strings.ToLower(os.Getenv("LC_ALL")); v != "" {
		return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
	}

	if v := strings.ToLower(os.Getenv("LC_CTYPE")); v != "" {
		return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
	}

	if v := strings.ToLower(os.Getenv("LANG")); v != "" {
		return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
	}

	// Default to true for modern systems, but you may set LANG=C or NO_UTF8 to force ASCII.
	if os.Getenv("NO_UTF8") != "" {
		return false
	}

	return true
}

// calcErrorRatePct computes error rate percentage from a Stats snapshot.
func calcErrorRatePct(s Stats) float64 {
	if s.Total <= 0 {
		return 0
	}

	err := s.HttpErrs + s.Mismatched + s.Aborted

	return (float64(err) / float64(s.Total)) * 100.0
}

var json = jsoniter.ConfigFastest

// Latency histogram in milliseconds: 0..60000 ms; >60s counted into overflow and clamped to last bucket
const maxLatencyMs = 60000

var latBuckets [maxLatencyMs + 1]int64 // index = ms

// --- Adaptive Auto-Mode helpers (Pacer) ---

// Pacer generates ticks at a configurable RPS and allows live reconfiguration.
// Important: It exposes a STABLE tick channel that remains valid across SetRPS calls.
type Pacer struct {
	mu    sync.Mutex
	rps   float64
	ch    chan time.Time
	stopC chan struct{}
}

func NewPacer(rps float64) *Pacer {
	p := &Pacer{
		ch:    make(chan time.Time, 1),
		stopC: make(chan struct{}),
	}

	if rps <= 0 {
		rps = 1 // ensure a sane default pacing when enabled
	}

	p.rps = rps

	go p.loop()

	return p
}

func (p *Pacer) loop() {
	for {
		// Capture current RPS atomically under mutex
		p.mu.Lock()
		r := p.rps
		p.mu.Unlock()

		// Compute sleep interval
		interval := time.Duration(float64(time.Second) / r)
		if interval <= 0 {
			interval = time.Nanosecond
		}

		select {
		case <-time.After(interval):
			// Non-blocking send to avoid piling up if consumer is slow
			select {
			case p.ch <- time.Now():
			default:
			}
		case <-p.stopC:
			return
		}
	}
}

// SetRPS updates the pacing rate. The exposed tick channel remains the same.
func (p *Pacer) SetRPS(rps float64) {
	if rps <= 0 {
		rps = 1
	}

	p.mu.Lock()
	p.rps = rps
	p.mu.Unlock()
}

// Tick returns a stable receive-only channel delivering pacing ticks.
func (p *Pacer) Tick() <-chan time.Time { return p.ch }

// Stop terminates the internal goroutine.
func (p *Pacer) Stop() { close(p.stopC) }

// TTY/Terminal Utilities
func isTTY() bool {
	fd := os.Stdout.Fd()

	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func termSize() (w, h int) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil || ws.Col == 0 || ws.Row == 0 {
		return 80, 24
	}

	return int(ws.Col), int(ws.Row)
}

// effectiveTermWidth returns the usable terminal width in columns.
// It prefers the provided termW (from termSize) when running on a TTY and termW>0,
// otherwise falls back to a safe default of 80 columns.
func effectiveTermWidth(termW int) int {
	if isTTY() && termW > 0 {
		return termW
	}

	return 80
}

// Display width helpers using runewidth so Unicode block characters render correctly.
func displayWidth(s string) int { return runewidth.StringWidth(s) }

// truncateToCells cuts a string to at most "max" display cells, preserving rune boundaries.
func truncateToCells(s string, max int) string { return runewidth.Truncate(s, max, "") }

// padToCellsRight pads the string with spaces on the right to reach exactly "w" display cells.
func padToCellsRight(s string, w int) string { return runewidth.FillRight(s, w) }

var latOverflow int64 // count of latencies > maxLatencyMs

// --- Adaptive state exposure for UI ---
// We expose current target RPS (as set by the controller) via an atomic uint64
// holding math.Float64bits, and the current desired concurrency via an int64.
var (
	tgtRPSBits  uint64 // atomic: math.Float64bits(current target rps); 0 = not set/unlimited
	desiredConc int64  // atomic: current desired concurrency in auto mode; 0 means fallback to configured
)

func setTargetRPS(v float64) { atomic.StoreUint64(&tgtRPSBits, math.Float64bits(v)) }
func getTargetRPS() float64  { return math.Float64frombits(atomic.LoadUint64(&tgtRPSBits)) }

// clamp01 confines a float value into the inclusive range [0,1].
func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}

	if x > 1 {
		return 1
	}

	return x
}

// helpers since generics/builtins may not be available in all build envs
func maxInt(a, b int) int {
	if a > b {
		return a
	}

	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}

	return b
}

// normalizeCtrlEvery ensures a sane controller cadence: (0, 5s].
func normalizeCtrlEvery(d time.Duration) time.Duration {
	if d <= 0 || d > 5*time.Second {
		return 5 * time.Second
	}

	return d
}

// applyRPS is the single point to set the current RPS both in the pacer and the exported target value.
// It clamps the value to >= 1 and returns the applied value.
func applyRPS(p *Pacer, r float64) float64 {
	if r <= 0 {
		r = 1
	}

	if p != nil {
		p.SetRPS(r)
	}

	setTargetRPS(r)

	return r
}

// Stats is a read-only snapshot of key counters and latency percentiles.
type Stats struct {
	Total, Matched, Mismatched, HttpErrs, Aborted, Skipped, ToleratedBF int64
	Avg, P50, P90, P99                                                  time.Duration
	Min, Max                                                            time.Duration
	Elapsed                                                             time.Duration
	TargetRPS                                                           float64
	Concurrency                                                         int64
}

// statsSnapshot is defined inside main() to atomically sample counters there.

// metricsLine holds the most recent single-line summary of server-side Lua/VM pool metrics.
// It is updated by the metrics poller and read by both the progress bar and periodic reporter.
var metricsLine atomic.Value // stores string

// deriveMetricsURL builds the /metrics endpoint URL from the provided API endpoint URL.
// It keeps scheme/host and replaces the path with "/metrics".
func deriveMetricsURL(apiURL string) string {
	u, err := url.Parse(apiURL)
	if err != nil {
		return ""
	}

	u.Path = "/metrics"
	u.RawQuery = ""
	u.Fragment = ""

	return u.String()
}

// parseLabels parses a Prometheus label set string including braces, e.g. {backend="default",key="backend:default"}.
// It returns a map of label key to unquoted value. Escapes inside quoted strings are handled.
func parseLabels(s string) map[string]string {
	m := map[string]string{}
	// Robustly split on commas outside of quoted segments and handle escaped quotes.
	var (
		key, val     string
		inKey, inVal bool
		inQuote, esc bool
	)

	add := func() {
		if key != "" {
			m[strings.TrimSpace(key)] = val
		}

		key, val = "", ""
	}

	inKey = true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inVal {
			if inQuote {
				if esc {
					val += string(c)
					esc = false

					continue
				}

				if c == '\\' {
					esc = true

					continue
				}

				if c == '"' {
					inQuote = false

					continue
				}

				val += string(c)

				continue
			}

			if c == ',' {
				add()
				inKey, inVal = true, false

				continue
			}

			if c == '"' {
				inQuote = true

				continue
			}

			if c == '}' {
				add()

				break
			}

			if !unicode.IsSpace(rune(c)) {
				val += string(c)
			}

			continue
		}

		if inKey {
			if c == '=' {
				inKey, inVal = false, true

				continue
			}

			if c == ',' {
				add()
				inKey, inVal = true, false

				continue
			}

			if c == '}' {
				add()

				break
			}

			if c == '{' {
				continue
			}

			if !unicode.IsSpace(rune(c)) {
				key += string(c)
			}

			continue
		}
	}

	if key != "" {
		add()
	}

	return m
}

// startMetricsPoller periodically fetches the Prometheus text endpoint and stores a compact summary line.
// The Authorization and other headers are copied from baseHeader so auth follows the existing client configuration.
func startMetricsPoller(ctx context.Context, httpClient *http.Client, metricsURL string, baseHeader http.Header, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}

	// Store initial placeholder for display components.
	metricsLine.Store("[metrics: collecting…]")

	// Track last seen values for counters to compute deltas.
	lastDropped := map[string]float64{}  // by backend
	lastReplaced := map[string]float64{} // by key

	// Precompile regexes for the metrics we care about to keep scan fast.
	wanted := []*regexp.Regexp{
		regexp.MustCompile(`^lua_queue_depth\b`),
		regexp.MustCompile(`^lua_queue_wait_seconds_(sum|count)\b`),
		regexp.MustCompile(`^lua_queue_dropped_total\b`),
		regexp.MustCompile(`^lua_vm_in_use\b`),
		regexp.MustCompile(`^lua_vm_replaced_total\b`),
	}

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				line := fetchAndFormatMetrics(ctx, httpClient, metricsURL, baseHeader, wanted, lastDropped, lastReplaced)
				if line == "" {
					line = "[metrics: n/a]"
				}

				metricsLine.Store(line)
			}
		}
	}()
}

// fetchAndFormatMetrics performs a single fetch of the Prometheus text exposition and returns a compact one-line summary.
func fetchAndFormatMetrics(ctx context.Context, httpClient *http.Client, metricsURL string, baseHeader http.Header, wanted []*regexp.Regexp, lastDropped, lastReplaced map[string]float64) string {
	if metricsURL == "" {
		return ""
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return ""
	}

	// Copy headers so metrics endpoint uses the same Authorization or other headers as load generation.
	for k, v := range baseHeader {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	// Prefer Prometheus text format v0.0.4
	req.Header.Set("Accept", "text/plain; version=0.0.4")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	// Aggregators
	depthByBackend := map[string]float64{}
	var waitSum, waitCount float64
	droppedByBackend := map[string]float64{}
	vmInUseByKey := map[string]float64{}
	replacedByKey := map[string]float64{}

	// Use a larger scanner buffer to handle large Prometheus pages (many series/buckets).
	scanner := bufio.NewScanner(resp.Body)
	// Initial buffer 64 KiB, max 10 MiB to be safe for large metric dumps.
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		matched := false
		for _, re := range wanted {
			if re.MatchString(line) {
				matched = true

				break
			}
		}

		if !matched {
			continue
		}

		// Split into metric head and value (ignore optional timestamp)
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		head := parts[0]
		valStr := parts[1]
		val, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			continue
		}

		name := head
		labels := map[string]string{}
		if i := strings.IndexByte(head, '{'); i >= 0 {
			name = head[:i]
			j := strings.LastIndexByte(head, '}')
			if j > i {
				labels = parseLabels(head[i : j+1])
			}
		}

		switch name {
		case "lua_queue_depth":
			b := labels["backend"]
			depthByBackend[b] += val
		case "lua_queue_wait_seconds_sum":
			waitSum += val
		case "lua_queue_wait_seconds_count":
			waitCount += val
		case "lua_queue_dropped_total":
			b := labels["backend"]
			droppedByBackend[b] = val
		case "lua_vm_in_use":
			k := labels["key"]
			vmInUseByKey[k] = val
		case "lua_vm_replaced_total":
			k := labels["key"]
			replacedByKey[k] = val
		}
	}

	// Helpers to select top-N
	type kv struct {
		k string
		v float64
	}

	pickTop := func(m map[string]float64, n int) []kv {
		a := make([]kv, 0, len(m))
		for k, v := range m {
			// Filter out zero values to avoid misleading "=0" entries when nothing is active.
			if v <= 0 {
				continue
			}

			a = append(a, kv{k, v})
		}

		sort.Slice(a, func(i, j int) bool { return a[i].v > a[j].v })
		if n > 0 && len(a) > n {
			a = a[:n]
		}

		return a
	}

	topsDepth := pickTop(depthByBackend, 3)
	topsVM := pickTop(vmInUseByKey, 3)
	// Totals across all series to provide a stable signal even if Top-N are filtered out
	var depthTotal float64
	for _, v := range depthByBackend {
		depthTotal += v
	}

	var vmInUseTotal float64
	for _, v := range vmInUseByKey {
		vmInUseTotal += v
	}

	avgWaitMs := 0.0
	if waitCount > 0 {
		avgWaitMs = (waitSum / waitCount) * 1000.0
	}

	// Compute deltas for counters
	droppedDeltaTotal := 0.0
	for b, cur := range droppedByBackend {
		prev := lastDropped[b]
		if cur >= prev {
			droppedDeltaTotal += (cur - prev)
		}

		lastDropped[b] = cur
	}

	replacedDeltaTotal := 0.0
	for k, cur := range replacedByKey {
		prev := lastReplaced[k]
		if cur >= prev {
			replacedDeltaTotal += cur - prev
		}

		lastReplaced[k] = cur
	}

	// Build compact one-liner. Fits in a single terminal line and is easy to scan during tests.
	var sb strings.Builder
	sb.WriteString("[lua qDepth: ")
	if len(topsDepth) == 0 {
		sb.WriteString("-")
	} else {
		for i, kv := range topsDepth {
			if i > 0 {
				sb.WriteString(",")
			}

			sb.WriteString(fmt.Sprintf("%s=%.0f", kv.k, kv.v))
		}
	}

	// Always include total depth as integer for quick glance
	sb.WriteString(fmt.Sprintf(" | total=%.0f] ", depthTotal))
	sb.WriteString("[qWait(avg)=")
	sb.WriteString(fmt.Sprintf("%.1fms] ", avgWaitMs))
	sb.WriteString("[dropped(Δ)=")
	sb.WriteString(fmt.Sprintf("%.0f] ", droppedDeltaTotal))
	sb.WriteString("[vmRepl(Δ)=")
	sb.WriteString(fmt.Sprintf("%.0f] ", replacedDeltaTotal))
	sb.WriteString("[vmInUse: ")

	if len(topsVM) == 0 {
		sb.WriteString("-")
	} else {
		for i, kv := range topsVM {
			if i > 0 {
				sb.WriteString(",")
			}

			sb.WriteString(fmt.Sprintf("%s=%.0f", kv.k, kv.v))
		}
	}

	// Include total in-use across all pools
	sb.WriteString(fmt.Sprintf(" | total=%.0f]", vmInUseTotal))

	// If scanner hit an error, still return whatever we aggregated so far.
	if err := scanner.Err(); err != nil {
		// On error, prefer a minimal marker to hint about partial metrics in the UI.
		// We keep the aggregated line but append a short note.
		s := sb.String()
		if s == "" {
			return "[metrics: error]"
		}

		return s + " [partial]"
	}

	return sb.String()
}

// computeHistogramCounts aggregates the global latency buckets into "cols" columns.
// The range [start..end] (inclusive, in ms) is partitioned into columns of size bucketSpan.
// It returns the per-column counts and the total across all considered buckets.
func computeHistogramCounts(start, end, bucketSpan, cols int) ([]int64, int64) {
	counts := make([]int64, cols)
	var total int64

	for i := 0; i < cols; i++ {
		lo := start + i*bucketSpan
		hi := lo + bucketSpan - 1
		if hi > end {
			hi = end
		}

		var c int64
		for b := lo; b <= hi; b++ {
			c += atomic.LoadInt64(&latBuckets[b])
		}

		counts[i] = c
		total += c
	}

	return counts, total
}

// percentileFromBuckets calculates a percentile duration from latBuckets within the range of 0 to maxLatencyMs in milliseconds.
func percentileFromBuckets(p float64) time.Duration {
	if p <= 0 {
		return 0
	}

	if p >= 1 {
		return time.Duration(maxLatencyMs) * time.Millisecond
	}

	// Sum of all observations
	var total int64
	for i := 0; i <= maxLatencyMs; i++ {
		total += atomic.LoadInt64(&latBuckets[i])
	}

	if total == 0 {
		return 0
	}

	// Target rank (1-based)
	target := int64(math.Ceil(float64(total) * p))

	var cum int64

	for i := 0; i <= maxLatencyMs; i++ {
		cum += atomic.LoadInt64(&latBuckets[i])
		if cum >= target {
			return time.Duration(i) * time.Millisecond
		}
	}

	// Fallback
	return time.Duration(maxLatencyMs) * time.Millisecond
}

// humanMs formats milliseconds for axis/labels (e.g., 123ms, 1.2s, 12s, 60s)
func humanMs(ms int) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}

	s := float64(ms) / 1000.0
	if s < 10 {
		return fmt.Sprintf("%.1fs", s)
	}

	return fmt.Sprintf("%ds", int(s+0.5))
}

// humanETA renders a fixed-width ETA string in format "hh:mm:ss" (8 chars).
// The value is clamped to [0, 99:59:59] to keep width stable.
func humanETA(d time.Duration) string {
	if d < 0 {
		d = 0
	}

	// Cap at 99:59:59 so width is stable and doesn't overflow
	maxDuration := 99*time.Hour + 59*time.Minute + 59*time.Second
	if d > maxDuration {
		d = maxDuration
	}

	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	s := int((d % time.Minute) / time.Second)

	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// humanCount formats large counts for Y-axis (e.g., 1.2k, 3.4M)
func humanCount(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}

	units := []string{"k", "M", "G", "T"}
	v := float64(n)

	for i, u := range units {
		threshold := math.Pow(1000, float64(i+1))
		if v < threshold*1000 || i == len(units)-1 {
			x := v / threshold
			if x < 10 {
				return fmt.Sprintf("%.1f%s", x, u)
			}

			return fmt.Sprintf("%.0f%s", x, u)
		}
	}

	return fmt.Sprintf("%d", n)
}

// findNonZeroRange finds the smallest and largest index with >0 occurrences in the histogram.
// Returns (startIdx, endIdx, ok). If ok==false, no data is present.
func findNonZeroRange() (int, int, bool) {
	start := -1
	end := -1
	for i := 0; i <= maxLatencyMs; i++ {
		if atomic.LoadInt64(&latBuckets[i]) != 0 {
			start = i

			break
		}
	}

	if start == -1 {
		return 0, 0, false
	}

	for i := maxLatencyMs; i >= 0; i-- {
		if atomic.LoadInt64(&latBuckets[i]) != 0 {
			end = i

			break
		}
	}

	return start, end, true
}

// printLatencyHistogramASCII renders a compact bar chart from the millisecond histogram.
// maxCols: maximum number of bars (pass 0 or negative to auto-fit using $COLUMNS), height: rows (e.g., 10)
// showMarkers: whether to show p50/p90/p99 as X-axis markers.
func printLatencyHistogramASCII(maxCols, height int, showMarkers bool) {
	if height < 1 {
		height = 10
	}

	dataStart, dataEnd, ok := findNonZeroRange()
	if !ok {
		fmt.Println("[hist] no data")

		return
	}

	// Small padding so the data range isn't glued to the border (used only for drawing bins)
	start := dataStart
	end := dataEnd
	pad := 0

	if end-start < 20 {
		pad = 2
	}

	start -= pad
	if start < 0 {
		start = 0
	}

	end += pad
	if end > maxLatencyMs {
		end = maxLatencyMs
	}

	span := end - start + 1
	dataSpan := dataEnd - dataStart + 1

	if dataSpan < 1 {
		dataSpan = 1
	}

	// Determine label width for Y axis and available columns using terminal width (COLUMNS)
	// Y-axis label shows counts, so width is based on max column height (maxC) once known; use a temporary width first
	labelWidth := 0 // will set after computing counts

	termW, _ := termSize()

	// we'll assume a minimal label width in the first pass (4) and a 2-char gutter: " "+"│"
	gutter := 2
	provisionalLabel := 4
	usable := 0

	if maxCols > 0 {
		usable = maxCols
	} else {
		widthAvail := effectiveTermWidth(termW)

		// leave space for labels + gutter; keep at least 20 bars
		usable = widthAvail - provisionalLabel - gutter
		if usable < 20 {
			usable = 20
		}
	}

	if span < usable {
		usable = span
	}

	bucketSpan := (span + usable - 1) / usable // ceil(span/usable) ms per column
	cols := (span + bucketSpan - 1) / bucketSpan

	counts, _ := computeHistogramCounts(start, end, bucketSpan, cols)

	// Max for scaling
	var maxC int64
	for _, c := range counts {
		if c > maxC {
			maxC = c
		}
	}

	if maxC == 0 {
		fmt.Println("[hist] all-zero buckets")

		return
	}

	// Now that we know maxC, set label width properly
	labelWidth = len(humanCount(maxC))
	if labelWidth < 4 {
		labelWidth = 4
	}

	// If auto width, recompute columns to fit terminal width exactly with real label width
	if maxCols <= 0 {
		widthAvail := effectiveTermWidth(termW)

		usable = widthAvail - labelWidth - gutter
		if usable < 20 {
			usable = 20
		}

		if span < usable {
			usable = span
		}

		bucketSpan = (span + usable - 1) / usable
		cols = (span + bucketSpan - 1) / bucketSpan
		counts, _ = computeHistogramCounts(start, end, bucketSpan, cols)

		// recompute maxC
		maxC = 0
		for _, c := range counts {
			if c > maxC {
				maxC = c
			}
		}

		if maxC == 0 {
			fmt.Println("[hist] all-zero buckets")

			return
		}

		labelWidth = len(humanCount(maxC))
		if labelWidth < 4 {
			labelWidth = 4
		}
	}

	// Optional: marker bin positions
	markerBin := map[string]int{}
	if showMarkers {
		p50 := int(percentileFromBuckets(0.50) / time.Millisecond)
		p90 := int(percentileFromBuckets(0.90) / time.Millisecond)
		p99 := int(percentileFromBuckets(0.99) / time.Millisecond)

		for label, ms := range map[string]int{"50": p50, "90": p90, "99": p99} {
			if ms < start {
				markerBin[label] = 0
			} else if ms > end {
				markerBin[label] = cols - 1
			} else {
				idx := (ms - start) / bucketSpan
				if idx < 0 {
					idx = 0
				}

				if idx >= cols {
					idx = cols - 1
				}

				markerBin[label] = idx
			}
		}
	}

	// Title line (concise; axes are labeled)
	fmt.Printf("Latency histogram  bins=%d height=%d\n", cols, height)

	// Determine drawing width (may be wider than number of data columns)
	drawCols := cols
	if maxCols <= 0 {
		widthAvail := effectiveTermWidth(termW)

		drawCols = widthAvail - labelWidth - gutter
		if drawCols < cols {
			drawCols = cols
		}
	}

	// Compute per-bin character width to fill drawing area
	colWidth := drawCols / cols
	if colWidth < 1 {
		colWidth = 1
	}

	rem := drawCols - colWidth*cols // distribute remainder to the first 'rem' bins

	// Precompute bin widths and starts in drawing space
	binWidths := make([]int, cols)
	binStarts := make([]int, cols)
	acc := 0

	for i := 0; i < cols; i++ {
		w := colWidth
		if i < rem {
			w++
		}

		binWidths[i] = w
		binStarts[i] = acc
		acc += w
	}

	// Print Y-axis header (right-aligned to labelWidth); color the axis arrow in blue
	fmt.Printf("%*s ", labelWidth, "count")
	fmt.Println(stAxis.S("↑"))

	// Bars from top to bottom with Y-axis labels
	for row := height; row >= 1; row-- {
		// threshold for this row
		thr := int64(math.Round(float64(maxC) * float64(row) / float64(height)))
		fmt.Printf("%*s ", labelWidth, humanCount(thr))
		// Color the Y-axis separator
		fmt.Print(stAxis.S("│"))

		for i := 0; i < cols; i++ {
			// height for this column in rows
			h := int(math.Round(float64(counts[i]) / float64(maxC) * float64(height)))
			w := binWidths[i]

			if h >= row {
				for k := 0; k < w; k++ {
					fmt.Print("█")
				}
			} else {
				for k := 0; k < w; k++ {
					fmt.Print(" ")
				}
			}
		}

		fmt.Println()
	}

	// X axis with ticks over drawing width; color the axis glyphs in blue
	fmt.Printf("%*s ", labelWidth, "")
	fmt.Print(stAxis.S("└"))

	// precompute tick positions at 0%,25%,50%,75%,100% in drawing space
	tickPos := []int{0, int(math.Round(float64(drawCols-1) * 0.25)), int(math.Round(float64(drawCols-1) * 0.5)), int(math.Round(float64(drawCols-1) * 0.75)), drawCols - 1}

	for x := 0; x < drawCols; x++ {
		isTick := false
		for _, t := range tickPos {
			if x == t {
				isTick = true

				break
			}
		}

		if isTick {
			fmt.Print(stAxis.S("┬"))
		} else {
			fmt.Print(stAxis.S("─"))
		}
	}

	fmt.Println()

	// Marker line (optional) aligned with X-axis, render labels "p50", "p90", "p99"
	if showMarkers {
		fmt.Printf("%*s  ", labelWidth, "")

		line := make([]rune, drawCols)
		for i := range line {
			line[i] = ' '
		}

		// helper to place a label centered in a bin span
		place := func(bin int, text string) {
			if bin < 0 || bin >= cols {
				return
			}

			start := binStarts[bin]
			width := binWidths[bin]

			if width <= 0 {
				return
			}

			t := []rune(text)

			pos := start + (width-len(t))/2
			if pos < 0 {
				pos = 0
			}

			for i, r := range t {
				p := pos + i
				if p >= 0 && p < len(line) {
					line[p] = r
				}
			}
		}

		// Place in order of increasing priority so later ones can overwrite if overlapping
		place(markerBin["50"], "p50")
		place(markerBin["90"], "p90")
		place(markerBin["99"], "p99")

		fmt.Println(string(line))
	}

	// X-axis labels line (start, 25%, 50%, 75%, end with humanMs) aligned to drawing width
	// Important: labels must reflect actual observed data range [dataStart,dataEnd], not padded drawing range
	fmt.Printf("%*s  ", labelWidth, "ms")

	last := 0
	nTicks := len(tickPos)
	for i, x := range tickPos {
		msVal := dataStart + int(math.Round(float64(x)/float64(drawCols-1)*float64(dataSpan-1)))
		if x == drawCols-1 {
			msVal = dataEnd
		}

		label := humanMs(msVal)

		// Compute desired position. For the last tick, right-align the label within drawCols
		// so it doesn't get cut off by the terminal edge.
		pos := x
		if i == nTicks-1 || x == drawCols-1 {
			rightAligned := drawCols - len(label)
			if rightAligned < 0 {
				rightAligned = 0
			}
			pos = rightAligned
		}

		// Do not move backward and overwrite previous labels
		if pos < last {
			pos = last
		}

		spaces := pos - last
		for k := 0; k < spaces; k++ {
			fmt.Print(" ")
		}

		fmt.Print(label)
		last = pos + len(label)
	}

	fmt.Println()

	// Extra info: max bin and overflow
	var maxIdx int
	for i := 0; i < cols; i++ {
		if counts[i] == maxC {
			maxIdx = i

			break
		}
	}

	binLoMs := start + maxIdx*bucketSpan

	binHiMs := binLoMs + bucketSpan - 1
	if binHiMs > end {
		binHiMs = end
	}

	of := atomic.LoadInt64(&latOverflow)

	if of > 0 {
		fmt.Printf("max_bin_count=%d in [%s,%s]  overflow(>%dms)=%d\n", maxC, humanMs(binLoMs), humanMs(binHiMs), maxLatencyMs, of)
	} else {
		fmt.Printf("max_bin_count=%d in [%s,%s]\n", maxC, humanMs(binLoMs), humanMs(binHiMs))
	}
}

// uint32ToIP converts uint32 to dotted IPv4 string.
func uint32ToIP(u uint32) string {
	b := []byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)}

	return net.IP(b).String()
}

// forbiddenRanges holds non-globally-routable IPv4 ranges [start,end] inclusive.
var forbiddenRanges = [][2]uint32{
	// 0.0.0.0/8
	{0x00000000, 0x00FFFFFF},
	// 10.0.0.0/8 private
	{0x0A000000, 0x0AFFFFFF},
	// 100.64.0.0/10 CGNAT
	{0x64400000, 0x647FFFFF},
	// 127.0.0.0/8 loopback
	{0x7F000000, 0x7FFFFFFF},
	// 169.254.0.0/16 link-local
	{0xA9FE0000, 0xA9FEFFFF},
	// 172.16.0.0/12 private
	{0xAC100000, 0xAC1FFFFF},
	// 192.0.0.0/24 IETF Protocol Assignments
	{0xC0000000, 0xC00000FF},
	// 192.0.2.0/24 TEST-NET-1
	{0xC0000200, 0xC00002FF},
	// 192.88.99.0/24 6to4 Relay Anycast (deprecated)
	{0xC0586300, 0xC05863FF},
	// 192.168.0.0/16 private
	{0xC0A80000, 0xC0A8FFFF},
	// 198.18.0.0/15 benchmarking
	{0xC6120000, 0xC613FFFF},
	// 198.51.100.0/24 TEST-NET-2
	{0xC6336400, 0xC63364FF},
	// 203.0.113.0/24 TEST-NET-3
	{0xCB007100, 0xCB0071FF},
	// 224.0.0.0/4 multicast
	{0xE0000000, 0xEFFFFFFF},
	// 240.0.0.0/4 reserved
	{0xF0000000, 0xFFFFFFFF},
	// 255.255.255.255/32 broadcast (already included above, but keep explicit)
	{0xFFFFFFFF, 0xFFFFFFFF},
}

// isRoutableIPv4 determines if the given IPv4 address (in uint32 format) is globally routable.
// It checks the address against a set of predefined forbidden ranges and returns false if it falls within any range.
func isRoutableIPv4(u uint32) bool {
	for _, r := range forbiddenRanges {
		if u >= r[0] && u <= r[1] {
			return false
		}
	}

	return true
}

// randomRoutableIPv4 returns a random globally-routable IPv4 address.
func randomRoutableIPv4() uint32 {
	for {
		u := rand.Uint32()
		if isRoutableIPv4(u) {
			return u
		}
	}
}

// maskFromPrefix returns a uint32 mask for a given prefix length (8..30).
func maskFromPrefix(prefix int) uint32 {
	if prefix <= 0 {
		return 0
	}

	if prefix > 32 {
		prefix = 32
	}

	return ^uint32(0) << (32 - prefix)
}

// overlaps reports whether [a1,a2] overlaps [b1,b2].
func overlaps(a1, a2, b1, b2 uint32) bool {
	return !(a2 < b1 || b2 < a1)
}

// pickRoutableCIDR tries to pick a globally routable IPv4 CIDR of given prefix such that the whole block avoids forbidden ranges.
func pickRoutableCIDR(prefix int) (baseNet uint32, mask uint32, ok bool) {
	mask = maskFromPrefix(prefix)

	// Try multiple attempts to find a clean block
	for attempts := 0; attempts < 2000; attempts++ {
		ip := randomRoutableIPv4()
		netStart := ip & mask
		netEnd := netStart | ^mask
		clean := true

		for _, fr := range forbiddenRanges {
			if overlaps(netStart, netEnd, fr[0], fr[1]) {
				clean = false

				break
			}
		}

		if clean {
			return netStart, mask, true
		}
	}

	return 0, 0, false
}

// randomHostInCIDR picks a random host address within the CIDR, avoiding network/broadcast where possible.
func randomHostInCIDR(baseNet uint32, mask uint32) uint32 {
	netStart := baseNet & mask
	netEnd := netStart | ^mask

	// If block is larger than 2 addresses, avoid network and broadcast
	if netEnd-netStart+1 > 2 {
		lo := netStart + 1
		hi := netEnd - 1
		span := hi - lo + 1

		return lo + uint32(rand.Int64N(int64(span)))
	}

	// Otherwise, pick any routable within block
	for attempts := 0; attempts < 100; attempts++ {
		u := netStart + uint32(rand.IntN(int(netEnd-netStart+1)))
		if isRoutableIPv4(u) {
			return u
		}
	}

	return netStart
}

type Row struct {
	Fields     map[string]string
	ExpectedOK bool
}

// parseBool parses a string into a boolean value based on common true/false representations. Returns an error for invalid input.
func parseBool(s string) (bool, error) {
	s = strings.TrimSpace(strings.ToLower(s))

	switch s {
	case "1", "true", "yes", "y":
		return true, nil
	case "0", "false", "no", "n":
		return false, nil
	}

	return false, fmt.Errorf("invalid bool: %q", s)
}

// readCSV reads a CSV file with optional delimiter and debug printing.
// If delim == 0, it auto-detects using the header line (comma, semicolon, or tab).
func readCSV(path string, delim rune, debug bool) ([]Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	br := bufio.NewReaderSize(f, 1<<20)

	// Peek first line to detect delimiter if needed
	firstLine, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	firstLine = strings.TrimRight(firstLine, "\r\n")
	// Auto-detect delimiter
	if delim == 0 {
		counts := map[rune]int{',': strings.Count(firstLine, ","), ';': strings.Count(firstLine, ";"), '\t': strings.Count(firstLine, "\t")}
		best := ','
		bestN := -1

		for d, n := range counts {
			if n > bestN {
				best = d
				bestN = n
			}
		}

		delim = best
	}

	// Rebuild a reader that starts from the beginning
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}

	br = bufio.NewReaderSize(f, 1<<20)
	cr := csv.NewReader(br)
	cr.ReuseRecord = false
	cr.TrimLeadingSpace = true
	cr.Comma = delim

	head, err := cr.Read()
	if err != nil {
		return nil, err
	}

	// Normalize headers: trim, lowercase, strip possible UTF-8 BOM on the first header
	for i := range head {
		h := strings.TrimSpace(head[i])
		if i == 0 {
			// Remove UTF-8 BOM if present (\uFEFF)
			h = strings.TrimPrefix(h, "\uFEFF")
		}

		head[i] = strings.ToLower(h)
	}

	// IMPORTANT: copy header slice because csv.Reader with ReuseRecord=true reuses the buffer
	hdr := make([]string, len(head))
	copy(hdr, head)

	if debug {
		fmt.Printf("[csv] detected delimiter=%q headers=%v\n", string(delim), hdr)
	}

	posExpected := -1
	for i, h := range hdr {
		if strings.EqualFold(h, "expected_ok") {
			posExpected = i

			break
		}
	}

	if posExpected < 0 {
		return nil, errors.New("CSV must contain expected_ok column")
	}

	var rows []Row
	rowNum := 1

	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		rowNum++

		m := make(map[string]string, len(rec))
		for i, h := range hdr {
			if i < len(rec) {
				m[h] = strings.TrimSpace(rec[i])
			}
		}

		ok, err := parseBool(m[hdr[posExpected]])
		if err != nil {
			return nil, fmt.Errorf("row %d expected_ok: %w", rowNum, err)
		}

		if debug && rowNum == 2 { // print first data row
			fmt.Printf("[csv] first row username=%q fields=%v\n", resolveUsername(m), m)
		}

		rows = append(rows, Row{Fields: m, ExpectedOK: ok})
	}

	return rows, nil
}

// Allowed JSON keys per server/model/authdto/json_request.go
var allowedKeys = map[string]struct{}{
	"username":              {},
	"password":              {},
	"client_ip":             {},
	"client_port":           {},
	"client_hostname":       {},
	"client_id":             {},
	"user_agent":            {},
	"local_ip":              {},
	"local_port":            {},
	"protocol":              {},
	"method":                {},
	"auth_login_attempt":    {},
	"ssl":                   {},
	"ssl_session_id":        {},
	"ssl_client_verify":     {},
	"ssl_client_dn":         {},
	"ssl_client_cn":         {},
	"ssl_issuer":            {},
	"ssl_client_notbefore":  {},
	"ssl_client_notafter":   {},
	"ssl_subject_dn":        {},
	"ssl_issuer_dn":         {},
	"ssl_client_subject_dn": {},
	"ssl_client_issuer_dn":  {},
	"ssl_protocol":          {},
	"ssl_cipher":            {},
	"ssl_serial":            {},
	"ssl_fingerprint":       {},
	"oidc_cid":              {},
}

// resolveUsername tries common CSV synonyms if "username" is missing or empty
func resolveUsername(fields map[string]string) string {
	if fields == nil {
		return ""
	}

	cand := []string{"username", "account", "user", "login", "email"}
	for _, k := range cand {
		if v, ok := fields[k]; ok {
			v = strings.TrimSpace(v)
			if v != "" {
				return v
			}
		}
	}

	return ""
}

// makePayload filters and processes input fields, converting keys to lowercase, validating against allowedKeys.
// It formats specific keys like "auth_login_attempt" and ensures "username" is resolved using common synonyms.
func makePayload(fields map[string]string) map[string]any {
	p := map[string]any{}

	for k, v := range fields {
		lk := strings.ToLower(strings.TrimSpace(k))
		if _, ok := allowedKeys[lk]; !ok {
			continue
		}

		if lk == "auth_login_attempt" {
			if v == "" {
				continue
			}

			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				p[lk] = n

				continue
			}
		}

		p[lk] = v
	}

	// Ensure username is present using common synonyms
	if uname := resolveUsername(fields); uname != "" {
		p["username"] = uname
	}

	return p
}

// generateCSV creates a CSV file at the specified path with a given number of rows based on predefined test data patterns.
// It returns an error if file creation or writing fails.
func generateCSV(path string, total int, cidrProb float64, cidrPrefix int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	// Full header as used in the example CSV and accepted by the client
	fmt.Fprintln(w, "username,password,client_ip,expected_ok,user_agent,protocol,method,ssl,ssl_protocol,ssl_cipher,ssl_client_verify,ssl_client_cn")

	// Validate inputs for CIDR grouping
	if cidrProb < 0 {
		cidrProb = 0
	}

	if cidrProb > 1 {
		cidrProb = 1
	}

	if cidrPrefix < 8 {
		cidrPrefix = 8
	}

	if cidrPrefix > 30 {
		cidrPrefix = 30
	}

	protocols := []string{"imap", "smtp", "pop3", "http"}
	methods := []string{"PLAIN", "LOGIN"}
	sslProtocols := []string{"TLSv1.2", "TLSv1.3"}
	sslCiphers := []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"}

	// Prepare a shared routable CIDR if requested
	var haveCIDR bool
	var baseNet uint32
	var mask uint32

	if cidrProb > 0 {
		if bn, m, ok := pickRoutableCIDR(cidrPrefix); ok {
			haveCIDR = true
			baseNet, mask = bn, m
		}
	}

	for i := 1; i <= total; i++ {
		username := fmt.Sprintf("user%05d", i)
		password := fmt.Sprintf("pw%05d", i)

		// Decide IP generation mode
		var ipU32 uint32
		if haveCIDR && rand.Float64() < cidrProb {
			ipU32 = randomHostInCIDR(baseNet, mask)
		} else {
			ipU32 = randomRoutableIPv4()
		}

		clientIP := uint32ToIP(ipU32)

		// Alternate expected_ok
		expected := "false"
		if i%2 == 1 {
			expected = "true"
		}

		userAgent := "NauthilusTestClient/1.0"
		protocol := protocols[(i-1)%len(protocols)]
		method := methods[(i-1)%len(methods)]

		// SSL related toggles
		ssl := "on"
		if i%3 == 0 {
			ssl = "off"
		}

		sslProtocol := sslProtocols[(i-1)%len(sslProtocols)]
		sslCipher := sslCiphers[(i-1)%len(sslCiphers)]

		// Simulate client verify alternating success/fail
		sslVerify := "SUCCESS"
		if i%5 == 0 {
			sslVerify = "FAIL"
		}

		sslCN := fmt.Sprintf("cn-%s", username)

		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			username,
			password,
			clientIP,
			expected,
			userAgent,
			protocol,
			method,
			ssl,
			sslProtocol,
			sslCipher,
			sslVerify,
			sslCN,
		)
	}

	return nil
}

func main() {
	var (
		csvPath         = flag.String("csv", "client/logins.csv", "CSV file path")
		endpoint        = flag.String("url", "http://localhost:8080/api/v1/auth/json", "Auth endpoint URL")
		method          = flag.String("method", "POST", "HTTP method")
		concurrency     = flag.Int("concurrency", 16, "Concurrent workers")
		rps             = flag.Float64("rps", 0, "Global rate limit (0=unlimited)")
		jitterMs        = flag.Int("jitter-ms", 0, "Random sleep 0..N ms before each request")
		delayMs         = flag.Int("delay-ms", 0, "Fixed delay per item in worker")
		timeoutMs       = flag.Int("timeout-ms", 5000, "HTTP timeout")
		maxRows         = flag.Int("max", 0, "Limit number of rows (0=all)")
		shuffle         = flag.Bool("shuffle", true, "Shuffle rows before sending")
		headersList     = flag.String("headers", "Content-Type: application/json", "Extra headers, separated by '||'")
		basicAuth       = flag.String("basic-auth", "", "HTTP Basic-Auth credentials in format username:password")
		okStatus        = flag.Int("ok-status", 200, "HTTP status indicating success when not using JSON flag")
		useJSONFlag     = flag.Bool("json-ok", true, "Expect JSON {ok:true|false} in response")
		verbose         = flag.Bool("v", false, "Verbose output")
		genCSV          = flag.Bool("generate-csv", false, "Generate a CSV at --csv path and exit")
		genCount        = flag.Int("generate-count", 10000, "Number of rows to generate when --generate-csv is set")
		genCIDRProb     = flag.Float64("generate-cidr-prob", 0.0, "Probability (0..1) that generated IPs are taken from the same CIDR block")
		genCIDRPrefix   = flag.Int("generate-cidr-prefix", 24, "CIDR prefix length (8..30) of the shared block for IP grouping")
		csvDelim        = flag.String("csv-delim", "", "CSV delimiter override: ',', ';', 'tab'; empty=auto-detect")
		csvDebug        = flag.Bool("csv-debug", false, "Print detected CSV headers and first row")
		loops           = flag.Int("loops", 1, "Number of cycles to run over the CSV")
		runFor          = flag.Duration("duration", 0, "Total duration to run the test (e.g. 5m). CSV rows will loop until time elapses")
		maxPar          = flag.Int("max-parallel", 1, "Max parallel requests per item (1=off)")
		parProb         = flag.Float64("parallel-prob", 0.0, "Probability (0..1) that an item is parallelized")
		abortProb       = flag.Float64("abort-prob", 0.0, "Probability (0..1) to abort/cancel a request (simulates connection drop)")
		progressEvery   = flag.Duration("progress-interval", time.Minute, "Progress report interval (e.g. 30s, 1m)")
		compareParallel = flag.Bool("compare-parallel", false, "Compare responses within a parallel group (strict byte equality)")
		useIdemKey      = flag.Bool("idempotency-key", false, "Add Idempotency-Key header computed from request body (SHA-256)")
		progressBar     = flag.Bool("progress-bar", false, "Render a single-line progress bar (TTY only)")
		colorMode       = flag.String("color", "auto", "Color output: auto|always|never")
		// Optional thresholds for coloring
		warnP95   = flag.Int("warn-p95", 300, "Warn threshold for p95 latency in ms")
		critP95   = flag.Int("crit-p95", 600, "Critical threshold for p95 latency in ms")
		warnErr   = flag.Float64("warn-error-rate", 0.5, "Warn threshold for error rate in %")
		critErr   = flag.Float64("crit-error-rate", 1.0, "Critical threshold for error rate in %")
		warnTrack = flag.Float64("warn-track", 0.85, "Warn threshold for tracking ratio rps/target_rps")
		critTrack = flag.Float64("crit-track", 0.70, "Critical threshold for tracking ratio rps/target_rps")

		// Graceful shutdown
		graceSeconds = flag.Int("grace-seconds", 10, "Graceful shutdown timeout before forcing cancel")

		// Auto-mode flags (adaptive pacing & concurrency)
		autoMode      = flag.Bool("auto", false, "Adaptive Auto-Mode for rps/concurrency")
		autoTargetP95 = flag.Int("auto-target-p95", 400, "Target p95 latency in ms")
		autoMaxRPS    = flag.Float64("auto-max-rps", 0, "Upper cap for auto rps (0=unlimited)")
		autoMaxConc   = flag.Int("auto-max-concurrency", 0, "Upper cap for auto concurrency (0=use --concurrency)")
		autoStartRPS  = flag.Float64("auto-start-rps", 1, "Starting RPS for auto mode")
		autoStartConc = flag.Int("auto-start-concurrency", 0, "Starting concurrency for auto mode (0=use --concurrency when focus=rps)")
		autoStepRPS   = flag.Float64("auto-step-rps", 5, "+RPS per window")
		autoStepConc  = flag.Int("auto-step-concurrency", 1, "+Concurrency per window")
		autoBackoff   = flag.Float64("auto-backoff", 0.7, "Multiplicative backoff factor on violation")
		autoMaxErr    = flag.Float64("auto-max-err", 1.0, "Max error rate in % per window")
		autoMinSample = flag.Int("auto-min-sample", 200, "Min requests per window to judge")
		autoFocus     = flag.String("auto-focus", "rps", "rps|concurrency|both")
		// Optional plateau detection flags
		autoPlateau         = flag.Bool("auto-plateau", false, "Enable plateau detection to pause increases when RPS gain stalls")
		autoPlateauWindows  = flag.Int("auto-plateau-windows", 3, "Number of control windows to detect a plateau (min 2)")
		autoPlateauGain     = flag.Float64("auto-plateau-gain", 5.0, "Minimum relative RPS gain in percent across the window; below this is considered a plateau")
		autoPlateauAction   = flag.String("auto-plateau-action", "freeze", "Action on plateau: freeze|backoff")
		autoPlateauCooldown = flag.Int("auto-plateau-cooldown", 2, "Cooldown windows after plateau before resuming increases")
		// Tracking-based plateau detection (rps vs trps)
		autoPlateauTrackThreshold = flag.Float64("auto-plateau-track-threshold", 0.9, "Tracking threshold rps/trps (0..1). Below this over N windows is considered a plateau")
		autoPlateauTrackWindows   = flag.Int("auto-plateau-track-windows", 0, "Windows for tracking plateau (0=use --auto-plateau-windows)")
		autoPlateauTrackAction    = flag.String("auto-plateau-track-action", "freeze", "Action on tracking plateau: freeze|backoff|shift (shift: pause RPS increases, raise concurrency)")
	)

	flag.Parse()

	// Decide color usage
	useColor := func() bool {
		switch strings.ToLower(strings.TrimSpace(*colorMode)) {
		case "always":
			return true
		case "never":
			return false
		default:
			return isTTY()
		}
	}()

	if os.Getenv("NO_COLOR") != "" {
		useColor = false
	}

	initColorStyles(useColor)

	// Sanitize concurrency
	if *concurrency < 1 {
		*concurrency = 1
	}

	// Generation mode: create synthetic CSV and exit
	if *genCSV {
		if err := generateCSV(*csvPath, *genCount, *genCIDRProb, *genCIDRPrefix); err != nil {
			panic(err)
		}

		fmt.Printf("generated %d rows into %s\n", *genCount, *csvPath)

		return
	}

	// Determine delimiter from flag
	var delim rune
	switch strings.ToLower(strings.TrimSpace(*csvDelim)) {
	case ",", "comma":
		delim = ','
	case ";", "semicolon":
		delim = ';'
	case "\t", "tab":
		delim = '\t'
	default:
		// auto-detect later
		delim = 0
	}

	rows, err := readCSV(*csvPath, delim, *csvDebug)
	if err != nil {
		panic(err)
	}

	if *maxRows > 0 && *maxRows < len(rows) {
		rows = rows[:*maxRows]
	}

	if *shuffle {
		rand.Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
	}

	// Precompute immutable per-row data to minimize per-request work in workers
	bodies := make([][]byte, len(rows))
	usernames := make([]string, len(rows))
	clientIPs := make([]string, len(rows))

	// Optional: per-row Idempotency-Key
	idemKeys := make([]string, len(rows))

	for i := range rows {
		usernames[i] = strings.TrimSpace(resolveUsername(rows[i].Fields))
		clientIPs[i] = strings.TrimSpace(rows[i].Fields["client_ip"])
		payload := makePayload(rows[i].Fields)
		bb, _ := json.Marshal(payload)
		bodies[i] = bb

		// Precompute Idempotency-Key if requested
		// We'll still guard usage at request time so this computation can be deferred if preferred.
		// But doing it here once per row is cheap and keeps worker hot path lean.
		if *useIdemKey {
			sum := sha256.Sum256(bb)
			idemKeys[i] = hex.EncodeToString(sum[:])
		}
	}

	// Expected results array for zero allocation in workers
	expectedOKs := make([]bool, len(rows))
	for i := range rows {
		expectedOKs[i] = rows[i].ExpectedOK
	}

	// High-performance HTTP transport tuned for load generation
	transport := &http.Transport{
		Proxy:                 nil, // skip env proxy lookup
		DialContext:           (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          8192,
		MaxIdleConnsPerHost:   8192,
		MaxConnsPerHost:       0, // unlimited
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,  // avoid gzip/deflate overhead
		ForceAttemptHTTP2:     false, // keep HTTP/1.1 unless server demands HTTP/2
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 0,
	}

	// Enable cookie handling: remember Set-Cookie across requests
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: time.Duration(*timeoutMs) * time.Millisecond, Transport: transport, Jar: jar}

	// Build base headers once and clone per request
	baseHeader := make(http.Header)

	for _, h := range strings.Split(*headersList, "||") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}

		kv := strings.SplitN(h, ":", 2)
		if len(kv) == 2 {
			baseHeader.Set(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
		}
	}

	// Make sure we don't receive compressed responses by default
	if baseHeader.Get("Accept-Encoding") == "" {
		baseHeader.Set("Accept-Encoding", "identity")
	}

	if baseHeader.Get("Content-Type") == "" {
		baseHeader.Set("Content-Type", "application/json")
	}

	// Apply HTTP Basic Auth if provided and not already set via --headers
	if *basicAuth != "" && baseHeader.Get("Authorization") == "" {
		enc := base64.StdEncoding.EncodeToString([]byte(*basicAuth))
		baseHeader.Set("Authorization", "Basic "+enc)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Metrics poller: always on. Auth for /metrics follows the existing headers (e.g., Basic/JWT) –
	// no extra flags required. This lets us display server-side Lua/VM pool metrics live during the test.
	metricsURL := deriveMetricsURL(*endpoint)
	startMetricsPoller(ctx, client, metricsURL, baseHeader, 5*time.Second)

	// Global stop flag (used for legacy checks in some loops)
	var stopFlag int32

	var total, matched, mismatched, httpErrs int64
	var skipped int64
	var toleratedBF int64
	var aborted int64
	var totalLatencyNs int64

	// Min/Max latency in ns
	var minLatencyNs int64 = math.MaxInt64
	var maxLatencyNs int64

	// HTTP status code histogram (0..599)
	var statusCounts [600]int64

	start := time.Now()

	// Define a local snapshot helper to avoid duplicating metric reads/derivations
	statsSnapshot := func() Stats {
		t := atomic.LoadInt64(&total)
		m := atomic.LoadInt64(&matched)
		mm := atomic.LoadInt64(&mismatched)
		he := atomic.LoadInt64(&httpErrs)
		ab := atomic.LoadInt64(&aborted)
		sk := atomic.LoadInt64(&skipped)
		bf := atomic.LoadInt64(&toleratedBF)
		tls := atomic.LoadInt64(&totalLatencyNs)

		var avg time.Duration
		if t > 0 {
			avg = time.Duration(tls / t)
		}

		concVal := atomic.LoadInt64(&desiredConc)
		if concVal <= 0 {
			concVal = int64(*concurrency)
		}

		return Stats{
			Total:       t,
			Matched:     m,
			Mismatched:  mm,
			HttpErrs:    he,
			Aborted:     ab,
			Skipped:     sk,
			ToleratedBF: bf,
			Avg:         avg,
			P50:         percentileFromBuckets(0.50),
			P90:         percentileFromBuckets(0.90),
			P99:         percentileFromBuckets(0.99),
			Min:         time.Duration(atomic.LoadInt64(&minLatencyNs)),
			Max:         time.Duration(atomic.LoadInt64(&maxLatencyNs)),
			Elapsed:     time.Since(start),
			TargetRPS:   getTargetRPS(),
			Concurrency: concVal,
		}
	}

	// Progress output: either interactive bar (TTY) or periodic text reporter
	const progressBarHz = 8 // fixed refresh rate for bar

	if isTTY() {
		fmt.Print("\x1b[2J\x1b[3J\x1b[H")
		fmt.Println("Running test...")
	}

	if *progressBar && isTTY() {
		// Interactive single-line progress bar pinned to the bottom (TTY only)
		go func() {
			defer func() {
				// Unhide cursor, clear line, print newline to separate final summary
				fmt.Printf("\x1b[?25h\r\x1b[2K\n")
			}()

			tick := time.NewTicker(time.Second / time.Duration(maxInt(1, progressBarHz)))
			defer tick.Stop()

			prevTotal := int64(0)
			prevTime := start

			// Determine planned total work
			var plannedTotal int64 = -1 // unknown
			if *runFor > 0 {
				plannedTotal = -2 // time-based
			} else {
				plannedTotal = int64(*loops * len(rows))
				if plannedTotal == 0 {
					plannedTotal = -1
				}
			}

			// Hide cursor to reduce flicker
			fmt.Printf("\x1b[?25l")

			for {
				select {
				case <-tick.C:
					now := time.Now()
					dt := now.Sub(prevTime).Seconds()
					if dt <= 0 {
						dt = 1
					}

					s := statsSnapshot()
					t := s.Total

					// RPS since last tick
					delta := t - prevTotal
					rps := float64(delta) / dt

					// Percentiles from snapshot
					p50 := s.P50
					p90 := s.P90

					// Progress ratio and left label
					var ratio float64
					var leftLabel string

					if plannedTotal == -2 { // duration-based
						if *runFor > 0 {
							ratio = float64(now.Sub(start)) / float64(*runFor)
							if ratio < 0 {
								ratio = 0
							}

							if ratio > 1 {
								ratio = 1
							}

							leftLabel = fmt.Sprintf("%3.0f%%", ratio*100)
						}
					} else if plannedTotal > 0 {
						ratio = float64(t) / float64(plannedTotal)
						if ratio > 1 {
							ratio = 1
						}

						leftLabel = fmt.Sprintf("%3.0f%% %d/%d", ratio*100, t, plannedTotal)
					} else {
						ratio = 0
						leftLabel = fmt.Sprintf("%d req", t)
					}

					termW, termH := termSize()
					// Build left and right parts
					left := leftLabel

					avgMs := int(s.Avg / time.Millisecond)
					p50Ms := int(p50 / time.Millisecond)
					p90Ms := int(p90 / time.Millisecond)

					// Determine current concurrency and target rps from snapshot
					concVal := s.Concurrency
					trps := s.TargetRPS
					var trkStr string

					if trps > 0 {
						trk := clamp01(rps / trps)

						trkStr = fmt.Sprintf(" [trk: %3.0f%%]", trk*100)
					} else {
						trkStr = ""
					}

					// ETA (fixed-width). For duration-based runs, show remaining time.
					// For count-based runs (known total), estimate based on current RPS.
					// Otherwise, display placeholder.
					etaStr := "--:--:--"
					if plannedTotal == -2 { // duration-based (--run-for)
						if *runFor > 0 {
							remain := (*runFor) - now.Sub(start)
							if remain < 0 {
								remain = 0
							}

							etaStr = humanETA(remain)
						}
					} else if plannedTotal > 0 { // count-based (known total)
						remain := plannedTotal - t
						if remain < 0 {
							remain = 0
						}

						if rps > 0 {
							etaDur := time.Duration(float64(remain) / rps * float64(time.Second))
							etaStr = humanETA(etaDur)
						}
					}

					right := fmt.Sprintf(
						"[eta: %s] [rps: %7.1f] [trps: %7d]%s [conc: %4d] [ok: %4s] [err: %s] [abort: %s] [skip: %s] [avg: %3s] [p50: %3s] [p90: %3s]",
						etaStr,
						rps,
						uint64(trps),
						trkStr,
						concVal,
						humanCount(s.Matched),
						humanCount(s.HttpErrs),
						humanCount(s.Aborted),
						humanCount(s.Skipped),
						humanMs(avgMs),
						humanMs(p50Ms),
						humanMs(p90Ms),
					)

					// Metrics one-liner from poller (always displayed)
					mline := metricsLine.Load()
					mstr, _ := mline.(string)
					if mstr == "" {
						mstr = "[metrics: n/a]"
					}

					// Compute coloring severity and plateau state
					errPct := calcErrorRatePct(s)
					trkRatio := 0.0
					if trps > 0 {
						trkRatio = clamp01(rps / trps)
					}

					severity := "ok"
					if s.P90 >= time.Duration(*critP95)*time.Millisecond || errPct >= *critErr || (trps > 0 && trkRatio <= *critTrack) {
						severity = "crit"
					} else if s.P90 >= time.Duration(*warnP95)*time.Millisecond || errPct >= *warnErr || (trps > 0 && trkRatio <= *warnTrack) {
						severity = "warn"
					}

					isPlateau := atomic.LoadInt32(&plateauActive) == 1

					// Header area under "Running test...":
					//  - Row 2: textual status (right string)
					//  - Row 3: metrics line
					hdr1 := " " + right
					if useColor {
						hdr1 = " " + stInfo.S(right)
					}

					if displayWidth(hdr1) < termW {
						hdr1 = padToCellsRight(hdr1, termW)
					} else {
						hdr1 = truncateToCells(hdr1, termW)
					}

					hdr2 := " " + mstr
					if useColor {
						hdr2 = " " + stDim.S(mstr)
					}
					if displayWidth(hdr2) < termW {
						hdr2 = padToCellsRight(hdr2, termW)
					} else {
						hdr2 = truncateToCells(hdr2, termW)
					}

					fmt.Printf("\x1b[s\x1b[2;1H\x1b[2K%s\x1b[3;1H\x1b[2K%s\x1b[u", hdr1, hdr2)

					// Bottom progress bar: left + BAR only (kept at the last row)
					const minBar = 10
					leftW := displayWidth(left)
					fixedSpaces := 2 // leading space + space before the bar
					available := termW - fixedSpaces - leftW

					if available < minBar {
						need := minBar - available
						newLeftW := leftW - need
						if newLeftW < 0 {
							newLeftW = 0
						}

						left = truncateToCells(left, newLeftW)
						leftW = displayWidth(left)
						available = termW - fixedSpaces - leftW
					}

					barWidth := available
					if barWidth < minBar {
						barWidth = minBar
					}

					fill := int(math.Round(ratio * float64(barWidth)))
					if fill < 0 {
						fill = 0
					}

					if fill > barWidth {
						fill = barWidth
					}

					// Left label coloring
					leftColored := left
					if useColor {
						switch {
						case isPlateau:
							leftColored = stPlate.S(left)
						case severity == "crit":
							leftColored = stCrit.S(left)
						case severity == "warn":
							leftColored = stWarn.S(left)
						default:
							leftColored = stOK.S(left)
						}
					}

					// Bar content and coloring (avoid slicing UTF-8 by bytes)
					// Choose characters based on terminal Unicode support
					useUni := supportsUnicode()
					fillChar := "#"
					emptyChar := "-"
					if useUni {
						fillChar = "█"
						emptyChar = "·"
					}
					if isPlateau {
						if useUni {
							fillChar = "▒"
						} else {
							fillChar = "="
						}
					}

					var bar string
					filled := ""
					rest := ""
					if fill > 0 {
						filled = strings.Repeat(fillChar, fill)
					}
					if barWidth-fill > 0 {
						rest = strings.Repeat(emptyChar, barWidth-fill)
					}

					if useColor {
						var c colorStyle
						switch {
						case isPlateau:
							c = stPlate
						case severity == "crit":
							c = stCrit
						case severity == "warn":
							c = stWarn
						default:
							c = stOK
						}

						if fill > 0 {
							bar = c.S(filled) + stDim.S(rest)
						} else {
							// no filled part; dim the entire bar
							bar = stDim.S(rest)
						}
					} else {
						bar = filled + rest
					}

					bottom := " " + leftColored + " " + bar

					if displayWidth(bottom) < termW {
						bottom = padToCellsRight(bottom, termW)
					} else {
						bottom = truncateToCells(bottom, termW)
					}

					if termH >= 1 {
						fmt.Printf("\x1b[s\x1b[%d;1H\x1b[2K%s\x1b[u", termH, bottom)
					}

					prevTotal = t
					prevTime = now
				case <-ctx.Done():
					return
				}
			}
		}()
	} else if *progressEvery > 0 {
		// Fallback: periodic text reporter (disabled when progress bar is active)
		go func() {
			ticker := time.NewTicker(*progressEvery)
			defer ticker.Stop()

			prevTotal := int64(0)
			prevTime := start

			for {
				select {
				case <-ticker.C:
					now := time.Now()
					dt := now.Sub(prevTime).Seconds()
					if dt <= 0 {
						dt = 1
					}

					s := statsSnapshot()
					t := s.Total

					delta := t - prevTotal
					rps := float64(delta) / dt
					elapsed := s.Elapsed
					trackRatio := 0.0
					if s.TargetRPS > 0 {
						trackRatio = clamp01(rps / s.TargetRPS)
					}

					// Severity and optional coloring for non-TTY reporter
					errPct := 0.0
					if t > 0 {
						errPct = (float64(s.HttpErrs+s.Mismatched+s.Aborted) / float64(t)) * 100
					}

					sev := "ok"
					if s.P90 >= time.Duration(*critP95)*time.Millisecond || errPct >= *critErr || (s.TargetRPS > 0 && trackRatio <= *critTrack) {
						sev = "crit"
					} else if s.P90 >= time.Duration(*warnP95)*time.Millisecond || errPct >= *warnErr || (s.TargetRPS > 0 && trackRatio <= *warnTrack) {
						sev = "warn"
					}

					label := "progress"
					if atomic.LoadInt32(&plateauActive) == 1 {
						if useColor {
							label = stPlate.S(label)
						} else {
							label = "plateau " + label
						}
					} else if useColor {
						switch sev {
						case "crit":
							label = stCrit.S(label)
						case "warn":
							label = stWarn.S(label)
						default:
							label = stOK.S(label)
						}
					}

					fmt.Printf("\n[%s %s] total=%d matched=%d mismatched=%d http_errors=%d aborted=%d skipped=%d tolerated_bf=%d rps=%.2f target_rps=%.f track_ratio=%.2f concurrency=%d avg_latency=%s min_latency=%s max_latency=%s p50=%s p90=%s p99=%s\n",
						label,
						elapsed.Truncate(time.Second), t, s.Matched, s.Mismatched, s.HttpErrs, s.Aborted, s.Skipped, s.ToleratedBF, rps, s.TargetRPS, trackRatio, s.Concurrency, s.Avg, s.Min, s.Max, s.P50, s.P90, s.P99,
					)

					// Always print the metrics one-liner as well so metrics are visible in non-TTY mode too.
					if ml := metricsLine.Load(); ml != nil {
						if mstr, ok := ml.(string); ok && mstr != "" {
							if useColor {
								fmt.Println(stDim.S(mstr))
							} else {
								fmt.Println(mstr)
							}
						}
					}

					prevTotal = t
					prevTime = now
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Configure brute-force header name (can be overridden via env BRUTEFORCE_HEADER_NAME)
	bfHeaderName := strings.TrimSpace(os.Getenv("BRUTEFORCE_HEADER_NAME"))
	if bfHeaderName == "" {
		bfHeaderName = "X-Nauthilus-Bruteforce"
	}

	// Worker function shared by both modes
	// Job carries grouping metadata for parallel comparison
	type job struct {
		rowIndex int
		groupID  uint64
		groupN   int
	}

	// Jobs channel capacity: allow larger buffer when auto-mode may raise concurrency
	jobsCap := *concurrency
	if *autoMode {
		capMax := *autoMaxConc
		if capMax <= 0 {
			capMax = *concurrency
		}

		if capMax > jobsCap {
			jobsCap = capMax
		}
	}

	jobs := make(chan job, jobsCap)

	// Track and safely close the current jobs channel
	var jobsMu sync.Mutex
	var jobsClosed bool

	closeJobsIfOpen := func() {
		jobsMu.Lock()
		defer jobsMu.Unlock()

		if !jobsClosed {
			close(jobs)
			jobsClosed = true
		}
	}

	// Graceful shutdown: signal to stop producing new jobs
	stopProduce := make(chan struct{})
	var stopProduceOnce sync.Once

	closeStopProduce := func() {
		stopProduceOnce.Do(func() {
			close(stopProduce)
		})
	}

	var wg sync.WaitGroup
	// buffered so reduceWorkers won't block if no worker is immediately selecting on quitCh
	quitCh := make(chan struct{}, 1024)
	// adaptive concurrency state and manager function placeholders
	var spawnWorkers func(int)
	var reduceWorkers func(int)

	// Parallel comparison state (only used when --compare-parallel)
	var (
		groupMu       sync.Mutex
		groupBodies   = make(map[uint64][][]byte)
		groupCodes    = make(map[uint64][]int)
		groupCTypes   = make(map[uint64][]string)
		groupExpected = make(map[uint64]int)
		groupSeq      uint64
	)

	var parallelMatched int64
	var parallelMismatched int64

	recordParallelResult := func(gid uint64, expected int, body []byte, code int, ctype string) {
		groupMu.Lock()
		defer groupMu.Unlock()

		groupBodies[gid] = append(groupBodies[gid], body)
		groupCodes[gid] = append(groupCodes[gid], code)
		groupCTypes[gid] = append(groupCTypes[gid], ctype)
		if _, ok := groupExpected[gid]; !ok {
			groupExpected[gid] = expected
		}

		if len(groupBodies[gid]) == groupExpected[gid] {
			baseB := groupBodies[gid][0]
			baseC := groupCodes[gid][0]
			baseT := groupCTypes[gid][0]
			same := true

			for i := 1; i < len(groupBodies[gid]); i++ {
				if !bytes.Equal(baseB, groupBodies[gid][i]) || baseC != groupCodes[gid][i] || baseT != groupCTypes[gid][i] {
					same = false
					break
				}
			}

			if same {
				atomic.AddInt64(&parallelMatched, 1)
			} else {
				atomic.AddInt64(&parallelMismatched, 1)
				if *verbose {
					fmt.Printf("PARALLEL MISMATCH group=%d samples=%d\n", gid, len(groupBodies[gid]))
				}
			}

			delete(groupBodies, gid)
			delete(groupCodes, gid)
			delete(groupCTypes, gid)
			delete(groupExpected, gid)
		}
	}

	worker := func() {
		defer wg.Done()

		// Per-worker reusable buffer to drain response bodies without per-request allocations
		buf := make([]byte, 32<<10)
		for {
			var jb job
			var ok bool
			select {
			case <-quitCh:
				return
			case jb, ok = <-jobs:
				if !ok {
					return
				}
			}

			idx := jb.rowIndex
			if *delayMs > 0 {
				time.Sleep(time.Duration(*delayMs) * time.Millisecond)
			}

			if *jitterMs > 0 {
				time.Sleep(time.Duration(rand.IntN(*jitterMs+1)) * time.Millisecond)
			}

			username := usernames[idx]
			clientIP := clientIPs[idx]
			bb := bodies[idx]

			// Skip rows with empty username to avoid server 400 (binding required field)
			if username == "" {
				atomic.AddInt64(&skipped, 1)

				if *verbose {
					fmt.Printf("SKIP row=%d reason=empty_username\n", idx)
				}

				continue
			}

			// Per-request cancellable context to simulate connection aborts
			reqCtx, reqCancel := context.WithCancel(ctx)
			var abortTimer *time.Timer

			willAbort := *abortProb > 0 && rand.Float64() < *abortProb
			if willAbort {
				// Choose a cancel delay in [0, timeout/2] ms to simulate mid-flight drop
				maxMs := *timeoutMs / 2
				if maxMs < 1 {
					maxMs = 1
				}

				d := time.Duration(rand.IntN(maxMs+1)) * time.Millisecond
				abortTimer = time.AfterFunc(d, reqCancel)
			}

			req, _ := http.NewRequestWithContext(reqCtx, *method, *endpoint, bytes.NewReader(bb))

			// copy base headers into a fresh map to avoid data races without Clone() churn
			req.Header = make(http.Header, len(baseHeader))

			for k, vs := range baseHeader {
				for _, v := range vs {
					req.Header.Add(k, v)
				}
			}

			// Worker function shared by both modes

			req.ContentLength = int64(len(bb))

			if clientIP != "" {
				req.Header.Set("X-Forwarded-For", clientIP)
			}

			// Optionally set Idempotency-Key header derived from request body
			if *useIdemKey {
				idemHeaderName := "Idempotency-Key"

				// Do not overwrite if already provided via --headers
				if req.Header.Get(idemHeaderName) == "" {
					key := idemKeys[idx]
					if key == "" {
						sum := sha256.Sum256(bb)
						key = hex.EncodeToString(sum[:])
						idemKeys[idx] = key
					}

					req.Header.Set(idemHeaderName, key)
				}
			}

			ts := time.Now()
			resp, err := client.Do(req)
			lat := time.Since(ts)

			// Update latency histogram (O(1))
			ms := int(lat / time.Millisecond)
			if ms < 0 {
				ms = 0
			}

			if ms > maxLatencyMs {
				atomic.AddInt64(&latOverflow, 1)

				ms = maxLatencyMs
			}

			atomic.AddInt64(&latBuckets[ms], 1)

			// Clean up cancel timer (do not cancel request context here)
			if abortTimer != nil {
				abortTimer.Stop()
			}

			// Important: do NOT call reqCancel() here in the success path.
			// Cancelling before the body is fully read can abort the connection mid-flight.
			// We'll cancel on error or after we've drained and closed the body below.

			atomic.AddInt64(&totalLatencyNs, int64(lat))
			atomic.AddInt64(&total, 1)

			// Update min/max latency atomically
			lns := int64(lat)
			// min
			for {
				old := atomic.LoadInt64(&minLatencyNs)
				if lns >= old {
					break
				}

				if atomic.CompareAndSwapInt64(&minLatencyNs, old, lns) {
					break
				}
			}

			// max
			for {
				old := atomic.LoadInt64(&maxLatencyNs)
				if lns <= old {
					break
				}

				if atomic.CompareAndSwapInt64(&maxLatencyNs, old, lns) {
					break
				}
			}

			if err != nil {
				// Distinguish simulated aborts from other HTTP errors
				if willAbort || errors.Is(err, context.Canceled) {
					atomic.AddInt64(&aborted, 1)

					if *verbose {
						fmt.Printf("ABORT user=%s err=%v lat=%s\n", username, err, lat)
					}
				} else {
					atomic.AddInt64(&httpErrs, 1)

					if *verbose {
						fmt.Printf("ERR user=%s err=%v lat=%s\n", username, err, lat)
					}
				}

				// Cancel per-request context on error to free resources
				reqCancel()

				continue
			}

			func() {
				defer resp.Body.Close()
				var gotOK bool

				code := resp.StatusCode
				ctype := resp.Header.Get("Content-Type")

				if *compareParallel {
					// We need raw bytes for comparison
					bodyBytes, _ := io.ReadAll(resp.Body)
					if *useJSONFlag {
						var jr struct {
							OK bool `json:"ok"`
						}

						_ = json.Unmarshal(bodyBytes, &jr)
						gotOK = jr.OK
					} else {
						gotOK = code == *okStatus
					}

					// Record for comparison if grouped
					if jb.groupID != 0 && jb.groupN > 1 {
						recordParallelResult(jb.groupID, jb.groupN, bodyBytes, code, ctype)
					}
				} else {
					if *useJSONFlag {
						var jr struct {
							OK bool `json:"ok"`
						}

						_ = json.NewDecoder(resp.Body).Decode(&jr)
						gotOK = jr.OK
					} else {
						gotOK = code == *okStatus
					}

					// Drain body with per-worker buffer to keep connections reusable without per-request allocs
					io.CopyBuffer(io.Discard, resp.Body, buf)
				}

				// Count HTTP status code
				if code >= 0 && code < len(statusCounts) {
					atomic.AddInt64(&statusCounts[code], 1)
				}

				if gotOK == expectedOKs[idx] {
					atomic.AddInt64(&matched, 1)

					if *verbose {
						fmt.Printf("OK user=%s status=%d lat=%s\n", username, resp.StatusCode, lat)
					}
				} else {
					// Respect brute-force header: tolerate mismatches if header is present
					bfHdr := resp.Header.Get(bfHeaderName)
					if bfHdr != "" {
						atomic.AddInt64(&matched, 1)
						atomic.AddInt64(&toleratedBF, 1)

						if *verbose {
							fmt.Printf("MISMATCH tolerated (bruteforce) user=%s expected=%v got=%v status=%d lat=%s header=%s\n", username, expectedOKs[idx], gotOK, resp.StatusCode, lat, bfHdr)
						}
					} else {
						atomic.AddInt64(&mismatched, 1)

						if *verbose {
							fmt.Printf("MISMATCH user=%s expected=%v got=%v status=%d lat=%s\n", username, expectedOKs[idx], gotOK, resp.StatusCode, lat)
						}
					}
				}
			}()

			// Now safe to cancel the request context after the response body has been fully consumed and closed
			reqCancel()
		}
	}

	// enqueueParallelGroup enqueues one or more parallel jobs for the same row index.
	// The first job follows the regular pacing (handled by caller); extra ones are enqueued immediately
	// with an optional tiny jitter to simulate parallel connection setup.
	enqueueParallelGroup := func(i int) {
		// Determine total jobs for this item
		total := 1
		if *maxPar > 1 && *parProb > 0 && rand.Float64() < *parProb {
			extra := rand.IntN(*maxPar) // 0..(maxPar-1)
			total += extra
		}

		var gid uint64
		if *compareParallel && total > 1 {
			gid = atomic.AddUint64(&groupSeq, 1)
		}

		// Enqueue jobs; stop gracefully if stopProduce is closed
		for k := 0; k < total; k++ {
			select {
			case <-stopProduce:
				// Stop producing and close jobs for workers to drain
				closeJobsIfOpen()

				return
			case jobs <- job{rowIndex: i, groupID: gid, groupN: total}:
			}
		}
	}

	// Now that worker() is defined, bind manager functions
	spawnWorkers = func(n int) {
		for i := 0; i < n; i++ {
			wg.Add(1)
			go worker()
		}
	}

	reduceWorkers = func(n int) {
		for i := 0; i < n; i++ {
			// signal one worker to exit
			quitCh <- struct{}{}
		}
	}

	// Graceful shutdown control
	var stopSigCount int32

	// Two-stage signal handler (graceful then force)
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			<-sigCh

			n := atomic.AddInt32(&stopSigCount, 1)

			if n == 1 {
				fmt.Println("\nInterrupt received. Finishing in-flight requests…")
				atomic.StoreInt32(&stopFlag, 1)

				// Stop producing new jobs and prevent new keep-alives
				closeStopProduce()
				transport.DisableKeepAlives = true

				// After grace timeout, force cancel if still running
				grace := time.Duration(maxInt(0, *graceSeconds)) * time.Second
				if grace > 0 {
					time.AfterFunc(grace, func() {
						if atomic.LoadInt32(&stopSigCount) < 2 {
							fmt.Println("\nGrace period elapsed. Forcing shutdown…")
							cancel()
						}
					})
				}
			} else {
				fmt.Println("\nSecond interrupt. Forcing shutdown now…")
				cancel()

				return
			}
		}
	}()

	// Prepare pacer (RPS limiter)
	var pacer *Pacer
	if *autoMode {
		startR := *autoStartRPS
		if startR <= 0 {
			startR = 1
		}

		pacer = NewPacer(startR)
		// ensure exported target value is in sync
		applyRPS(pacer, startR)
	} else if *rps > 0 {
		pacer = NewPacer(*rps)
		applyRPS(pacer, *rps)
	}

	// Duration mode: loop over CSV until time elapses
	if *runFor > 0 {
		var tick <-chan time.Time
		if pacer != nil {
			tick = pacer.Tick()
		}

		if *autoMode {
			// Start with configured or default concurrency
			initConc := *autoStartConc
			if initConc < 1 {
				// If focus is RPS only, start with the regular --concurrency to avoid underutilization
				if *autoFocus == "rps" && *concurrency > 0 {
					initConc = *concurrency
				} else {
					initConc = 1
				}
			}

			maxC := *autoMaxConc
			if maxC <= 0 {
				maxC = *concurrency
			}

			if initConc > maxC {
				initConc = maxC
			}

			atomic.StoreInt64(&desiredConc, int64(initConc))
			spawnWorkers(initConc)
		} else {
			spawnWorkers(*concurrency)
		}

		// Start adaptive controller if enabled (after workers are spawned)
		if *autoMode {
			startController := func(durationMode bool) {
				// Control cadence: at most every 5s to ramp faster regardless of progress interval
				ctrlEvery := normalizeCtrlEvery(*progressEvery)

				maxR := *autoMaxRPS
				if maxR < 0 {
					maxR = 0
				}

				maxC := *autoMaxConc
				if maxC <= 0 {
					maxC = *concurrency
				}

				currR := *autoStartRPS
				currR = applyRPS(pacer, currR)

				var lastTotal = atomic.LoadInt64(&total)
				var lastErrs = atomic.LoadInt64(&httpErrs) + atomic.LoadInt64(&aborted)

				go func() {
					tk := time.NewTicker(ctrlEvery)
					defer tk.Stop()
					// Plateau detection state
					var prevRPS float64
					var plateauStreak int
					var freezeWins int
					// Pause RPS increases only (for tracking action "shift")
					var freezeRPSWins int

					// Helpers to reduce duplicate logic
					incConcurrencyStep := func() {
						if *autoFocus != "rps" && durationMode {
							old := int(atomic.LoadInt64(&desiredConc))

							newC := old + *autoStepConc
							if maxC > 0 && newC > maxC {
								newC = maxC
							}

							if newC != old {
								spawnWorkers(newC - old)
								atomic.StoreInt64(&desiredConc, int64(newC))
							}
						}
					}

					backoffConcurrency := func() {
						if *autoFocus != "rps" && durationMode {
							old := int(atomic.LoadInt64(&desiredConc))
							newC := int(math.Ceil(float64(old) * (*autoBackoff)))
							if newC < 1 {
								newC = 1
							}

							if maxC > 0 && newC > maxC {
								newC = maxC
							}

							if newC != old {
								if newC > old {
									spawnWorkers(newC - old)
								} else {
									reduceWorkers(old - newC)
								}

								atomic.StoreInt64(&desiredConc, int64(newC))
							}
						}
					}

					applyPacerClamp := func() {
						if pacer != nil {
							if maxR > 0 && currR > maxR {
								currR = maxR
							}

							applyRPS(pacer, currR)
						}
					}

					for {
						select {
						case <-tk.C:
							tNow := atomic.LoadInt64(&total)
							eNow := atomic.LoadInt64(&httpErrs) + atomic.LoadInt64(&aborted)
							dt := tNow - lastTotal
							de := eNow - lastErrs
							lastTotal = tNow
							lastErrs = eNow
							// Scale min-sample to the control window. The default 1m window with 200 samples
							// becomes ~16-17 samples for a 5s window.
							effMin := int64(math.Max(1, math.Round(float64(*autoMinSample)*ctrlEvery.Seconds()/60.0)))

							if dt < effMin {
								// Too few samples to judge yet: ramp up optimistically to get signal
								if *autoFocus != "concurrency" {
									currR += *autoStepRPS
									if maxR > 0 && currR > maxR {
										currR = maxR
									}
								}

								if *autoFocus != "rps" && durationMode {
									incConcurrencyStep()
								}

								applyPacerClamp()

								continue
							}

							p95 := percentileFromBuckets(0.95)
							errPct := 100 * float64(de) / float64(maxInt64(1, dt))

							violate := errPct > *autoMaxErr || p95 > time.Duration(*autoTargetP95)*time.Millisecond
							if violate {
								currR = math.Max(1, currR*(*autoBackoff))
								backoffConcurrency()

								// Reset plateau state on violation
								plateauStreak = 0
								atomic.StoreInt32(&plateauActive, 0)
								// Do not change freezeWins here; backoff overrides freeze
							} else {
								// Plateau detection (optional), only when we have enough samples
								if *autoPlateau && *autoPlateauWindows >= 2 {
									// Compute current window RPS
									winRPS := float64(dt) / ctrlEvery.Seconds()
									thr := (*autoPlateauGain) / 100.0
									if thr < 0 {
										thr = 0
									}

									// Only evaluate if we have a previous RPS to compare
									if prevRPS > 0 {
										gain := (winRPS - prevRPS) / prevRPS
										if gain < thr {
											plateauStreak++
										} else {
											plateauStreak = 0
										}
									}

									prevRPS = winRPS
									if plateauStreak >= *autoPlateauWindows {
										plateauStreak = 0
										// Decide action
										switch strings.ToLower(strings.TrimSpace(*autoPlateauAction)) {
										case "backoff":
											currR = math.Max(1, currR*(*autoBackoff))
											backoffConcurrency()
											// No freeze after explicit backoff
											atomic.StoreInt32(&plateauActive, 1)
										default: // freeze
											if *autoPlateauCooldown > 0 {
												freezeWins = *autoPlateauCooldown
											} else {
												freezeWins = 1
											}
											atomic.StoreInt32(&plateauActive, 1)
										}
									}

									// Tracking-based plateau detection: sustained underdelivery rps<trps
									tw := *autoPlateauTrackWindows
									if tw <= 0 {
										tw = *autoPlateauWindows
									}

									if tw < 2 {
										tw = 2
									}

									if currR > 0 && tw >= 2 {
										track := winRPS / currR
										if track < *autoPlateauTrackThreshold {
											// Underdelivery
											plateauStreak++
										} else {
											plateauStreak = 0
										}

										if plateauStreak >= tw {
											plateauStreak = 0
											switch strings.ToLower(strings.TrimSpace(*autoPlateauTrackAction)) {
											case "backoff":
												currR = math.Max(1, currR*(*autoBackoff))
												backoffConcurrency()
												atomic.StoreInt32(&plateauActive, 1)
											case "shift":
												// Pause RPS increases; increase concurrency once (if allowed)
												if *autoPlateauCooldown > 0 {
													freezeRPSWins = *autoPlateauCooldown
												} else {
													freezeRPSWins = 1
												}

												incConcurrencyStep()
												atomic.StoreInt32(&plateauActive, 1)
											default: // freeze
												if *autoPlateauCooldown > 0 {
													freezeWins = *autoPlateauCooldown
												} else {
													freezeWins = 1
												}
												atomic.StoreInt32(&plateauActive, 1)
											}
										}
									}
								}

								// Apply increases only if not in freeze cooldown
								if freezeWins > 0 {
									freezeWins--
								} else {
									if *autoFocus != "concurrency" {
										if freezeRPSWins > 0 {
											freezeRPSWins--
										} else {
											currR += *autoStepRPS
											if maxR > 0 && currR > maxR {
												currR = maxR
											}
										}
									}

									if *autoFocus != "rps" && durationMode {
										old := int(atomic.LoadInt64(&desiredConc))

										newC := old + *autoStepConc
										if maxC > 0 && newC > maxC {
											newC = maxC
										}

										if newC != old {
											spawnWorkers(newC - old)
											atomic.StoreInt64(&desiredConc, int64(newC))
										}
									}
								}

								// Update plateauActive based on cooldowns
								if freezeWins > 0 || freezeRPSWins > 0 {
									atomic.StoreInt32(&plateauActive, 1)
								} else {
									atomic.StoreInt32(&plateauActive, 0)
								}
							}

							applyPacerClamp()
						case <-ctx.Done():
							return
						}
					}
				}()
			}

			startController(true)
		}

		deadline := time.Now().Add(*runFor)
	outerLoop:
		for i := 0; ; i = (i + 1) % len(rows) {
			if atomic.LoadInt32(&stopFlag) == 1 {
				break
			}

			// Graceful stop request: stop producing
			select {
			case <-stopProduce:
				break outerLoop
			default:
			}

			if time.Now().After(deadline) {
				break
			}

			if tick != nil {
				select {
				case <-tick:
				case <-stopProduce:
					break outerLoop
				case <-ctx.Done():
					break outerLoop
				}
			}

			enqueueParallelGroup(i)
		}

		closeJobsIfOpen()
		wg.Wait()

		if pacer != nil {
			pacer.Stop()
		}
	} else {
		// Legacy loops mode (kept for backward compatibility)
	outerCycles:
		for cycle := 1; cycle <= *loops; cycle++ {
			// Per-cycle rate limiter
			var tick <-chan time.Time
			if pacer != nil {
				tick = pacer.Tick()
			}

			// Start workers consistently via helper
			spawnWorkers(*concurrency)

			if *autoMode && cycle == 1 {
				// Start controller once for loops mode (RPS only)
				startController := func() {
					// Faster cadence: at most every 5s
					ctrlEvery := normalizeCtrlEvery(*progressEvery)

					maxR := *autoMaxRPS
					if maxR < 0 {
						maxR = 0
					}

					currR := *autoStartRPS
					currR = applyRPS(pacer, currR)

					var lastTotal = atomic.LoadInt64(&total)
					var lastErrs = atomic.LoadInt64(&httpErrs) + atomic.LoadInt64(&aborted)
					go func() {
						tk := time.NewTicker(ctrlEvery)
						defer tk.Stop()

						// Plateau detection state (RPS-only in loops mode)
						var prevRPS float64
						var plateauStreak int
						var freezeWins int
						var freezeRPSWins int

						for {
							select {
							case <-tk.C:
								tNow := atomic.LoadInt64(&total)
								eNow := atomic.LoadInt64(&httpErrs) + atomic.LoadInt64(&aborted)
								dt := tNow - lastTotal
								de := eNow - lastErrs
								lastTotal = tNow
								lastErrs = eNow

								if dt < int64(*autoMinSample) {
									// Too few samples in this window: ramp RPS up optimistically
									currR += *autoStepRPS
									if maxR > 0 && currR > maxR {
										currR = maxR
									}

									if pacer != nil {
										applyRPS(pacer, currR)
									}

									continue
								}

								p95 := percentileFromBuckets(0.95)
								errPct := 100 * float64(de) / float64(maxInt64(1, dt))

								violate := errPct > *autoMaxErr || p95 > time.Duration(*autoTargetP95)*time.Millisecond
								if violate {
									currR = math.Max(1, currR*(*autoBackoff))
									plateauStreak = 0
									atomic.StoreInt32(&plateauActive, 0)
								} else {
									// Plateau detection (optional)
									if *autoPlateau && *autoPlateauWindows >= 2 {
										winRPS := float64(dt) / ctrlEvery.Seconds()

										thr := (*autoPlateauGain) / 100.0
										if thr < 0 {
											thr = 0
										}

										if prevRPS > 0 {
											gain := (winRPS - prevRPS) / prevRPS
											if gain < thr {
												plateauStreak++
											} else {
												plateauStreak = 0
											}
										}

										prevRPS = winRPS
										if plateauStreak >= *autoPlateauWindows {
											plateauStreak = 0
											switch strings.ToLower(strings.TrimSpace(*autoPlateauAction)) {
											case "backoff":
												currR = math.Max(1, currR*(*autoBackoff))
												atomic.StoreInt32(&plateauActive, 1)
											default: // freeze
												if *autoPlateauCooldown > 0 {
													freezeWins = *autoPlateauCooldown
												} else {
													freezeWins = 1
												}
												atomic.StoreInt32(&plateauActive, 1)
											}
										}
										// Tracking-based plateau detection (rps<trps over N windows)
										tw := *autoPlateauTrackWindows
										if tw <= 0 {
											tw = *autoPlateauWindows
										}

										if tw < 2 {
											tw = 2
										}

										if currR > 0 && tw >= 2 {
											track := winRPS / currR
											if track < *autoPlateauTrackThreshold {
												plateauStreak++
											} else {
												plateauStreak = 0
											}

											if plateauStreak >= tw {
												plateauStreak = 0
												switch strings.ToLower(strings.TrimSpace(*autoPlateauTrackAction)) {
												case "backoff":
													currR = math.Max(1, currR*(*autoBackoff))
												case "shift":
													if *autoPlateauCooldown > 0 {
														freezeRPSWins = *autoPlateauCooldown
													} else {
														freezeRPSWins = 1
													}
												default: // freeze
													if *autoPlateauCooldown > 0 {
														freezeWins = *autoPlateauCooldown
													} else {
														freezeWins = 1
													}
												}
												atomic.StoreInt32(&plateauActive, 1)
											}
										}
									}

									if freezeWins > 0 {
										freezeWins--
									} else {
										if freezeRPSWins > 0 {
											freezeRPSWins--
										} else {
											currR += *autoStepRPS
											if maxR > 0 && currR > maxR {
												currR = maxR
											}
										}
									}
									// Update plateau flag based on cooldowns
									if freezeWins > 0 || freezeRPSWins > 0 {
										atomic.StoreInt32(&plateauActive, 1)
									} else {
										atomic.StoreInt32(&plateauActive, 0)
									}
								}

								if pacer != nil {
									if maxR > 0 && currR > maxR {
										currR = maxR
									}

									applyRPS(pacer, currR)
								}
							case <-ctx.Done():
								return
							}
						}
					}()
				}

				startController()
			}

			for i := range rows {
				if atomic.LoadInt32(&stopFlag) == 1 {
					closeJobsIfOpen()
					wg.Wait()

					break outerCycles
				}

				if tick != nil {
					select {
					case <-tick:
					case <-stopProduce:
						closeJobsIfOpen()
						wg.Wait()

						break outerCycles
					case <-ctx.Done():
						closeJobsIfOpen()
						wg.Wait()

						break outerCycles
					}
				}

				enqueueParallelGroup(i)
			}

			closeJobsIfOpen()
			wg.Wait()

			// Keep pacer running across cycles; controller adjusts it

			// Recreate jobs channel for next cycle
			if cycle != *loops {
				jobsCap = *concurrency
				if *autoMode {
					capMax := *autoMaxConc
					if capMax <= 0 {
						capMax = *concurrency
					}

					if capMax > jobsCap {
						jobsCap = capMax
					}
				}

				jobs = make(chan job, jobsCap)

				// Reset close state for the new channel
				jobsMu.Lock()
				jobsClosed = false
				jobsMu.Unlock()
			}
		}

		if pacer != nil {
			pacer.Stop()
		}
	}

	// Close idle connections after all workers are done
	transport.CloseIdleConnections()

	// Stop progress reporter
	cancel()

	dur := time.Since(start)

	// Option 1: Clear screen AND scrollback, then print the entire final output anew
	if isTTY() {
		fmt.Print("\x1b[2J\x1b[3J\x1b[H")
	}

	fmt.Printf("Done in %s\n", dur)
	fmt.Printf("total=%d matched=%d mismatched=%d http_errors=%d aborted=%d skipped=%d tolerated_bf=%d\n", total, matched, mismatched, httpErrs, aborted, skipped, toleratedBF)

	if dur > 0 {
		fmt.Printf("throughput=%.2f req/s\n", float64(total)/dur.Seconds())
	}

	// Auto-mode: print final controller targets for transparency
	if *autoMode {
		trps := getTargetRPS()

		concVal := atomic.LoadInt64(&desiredConc)
		if concVal <= 0 {
			concVal = int64(*concurrency)
		}

		fmt.Printf("final_target_rps=%.f final_concurrency=%d focus=%s\n", trps, concVal, *autoFocus)
	}

	if *compareParallel {
		fmt.Printf("parallel_matched=%d parallel_mismatched=%d\n", parallelMatched, parallelMismatched)
	}

	fmt.Println()

	if total > 0 {
		avg := time.Duration(totalLatencyNs / total)
		fmt.Printf("avg_latency=%s\n", avg)

		// Print min/max latencies
		if minLatencyNs != math.MaxInt64 {
			fmt.Printf("min_latency=%s\n", time.Duration(minLatencyNs))
		} else {
			fmt.Printf("min_latency=NA\n")
		}

		fmt.Printf("max_latency=%s\n", time.Duration(maxLatencyNs))

		fmt.Println()

		// Print percentiles from histogram
		p50 := percentileFromBuckets(0.50)
		p90 := percentileFromBuckets(0.90)
		p99 := percentileFromBuckets(0.99)

		fmt.Printf("p50=%s p90=%s p99=%s\n", p50, p90, p99)
		fmt.Println()

		of := atomic.LoadInt64(&latOverflow)
		if of > 0 {
			fmt.Printf("latency_overflow(>%dms)=%d\n", maxLatencyMs, of)
		}

		// Print HTTP status codes summary (code, count)
		fmt.Println("http_status_counts:")
		for code, cnt := range statusCounts {
			if cnt != 0 {
				fmt.Printf("  %d: %d\n", code, cnt)
			}
		}

		// ASCII histogram (60 columns, 10 rows); print only in TTY contexts
		if isTTY() {
			fmt.Println()
			printLatencyHistogramASCII(0, 10, true)
			fmt.Println()
		}
	}
}
