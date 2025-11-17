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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/mattn/go-isatty"
	"github.com/mattn/go-runewidth"
	"golang.org/x/sys/unix"
)

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

	// Print Y-axis header (right-aligned to labelWidth)
	fmt.Printf("%*s %c\n", labelWidth, "count", '↑')

	// Bars from top to bottom with Y-axis labels
	for row := height; row >= 1; row-- {
		// threshold for this row
		thr := int64(math.Round(float64(maxC) * float64(row) / float64(height)))
		fmt.Printf("%*s ", labelWidth, humanCount(thr))
		fmt.Print("│")

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

	// X axis with ticks over drawing width
	fmt.Printf("%*s └", labelWidth, "")

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
			fmt.Print("┬")
		} else {
			fmt.Print("─")
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
	Fields     map[string]string // alle CSV-Felder pro Zeile
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

	// Handle Ctrl+C (SIGINT) and SIGTERM to print results on interrupt
	var stopFlag int32

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh

		fmt.Println("\nInterrupt received, stopping...")
		atomic.StoreInt32(&stopFlag, 1)

		cancel()
	}()

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

			tick := time.NewTicker(time.Second / time.Duration(max(1, progressBarHz)))
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

					t := atomic.LoadInt64(&total)
					m := atomic.LoadInt64(&matched)
					he := atomic.LoadInt64(&httpErrs)
					ab := atomic.LoadInt64(&aborted)
					sk := atomic.LoadInt64(&skipped)
					tls := atomic.LoadInt64(&totalLatencyNs)

					var avg time.Duration
					if t > 0 {
						avg = time.Duration(tls / t)
					}

					// RPS since last tick
					delta := t - prevTotal
					rps := float64(delta) / dt

					// Percentiles
					p50 := percentileFromBuckets(0.50)
					p90 := percentileFromBuckets(0.90)

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

					avgMs := int(avg / time.Millisecond)
					p50Ms := int(p50 / time.Millisecond)
					p90Ms := int(p90 / time.Millisecond)

					// Determine current concurrency (auto mode may adjust it)
					concVal := atomic.LoadInt64(&desiredConc)
					if concVal <= 0 {
						concVal = int64(*concurrency)
					}

					trps := getTargetRPS()
					var trkStr string
					if trps > 0 {
						trk := rps / trps
						if trk > 1 {
							trk = 1
						}

						if trk < 0 {
							trk = 0
						}

						trkStr = fmt.Sprintf(" [trk: %3.0f%%]", trk*100)
					} else {
						trkStr = ""
					}

					right := fmt.Sprintf(
						" [rps: %7.1f] [trps: %7d]%s [conc: %4d] [ok: %4s] [err: %s] [abort: %s] [skip: %s] [avg: %3s] [p50: %3s] [p90: %3s]",
						rps,
						uint64(trps),
						trkStr,
						concVal,
						humanCount(m),
						humanCount(he),
						humanCount(ab),
						humanCount(sk),
						humanMs(avgMs),
						humanMs(p50Ms),
						humanMs(p90Ms),
					)

					// Two-line layout:
					//   Top:    right (status, RPS, counters, latencies)
					//   Bottom: left + BAR (no right)
					const minBar = 10
					leftW := displayWidth(left)

					// Width available for the bar (exclude right completely)
					fixedSpaces := 2 // leading space + space before the bar
					available := termW - fixedSpaces - leftW

					if available < minBar {
						// If needed, shrink left label to keep a minimal bar width
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

					// Compute fill length rounded to nearest cell
					fill := int(math.Round(ratio * float64(barWidth)))
					if fill < 0 {
						fill = 0
					}

					if fill > barWidth {
						fill = barWidth
					}

					bar := strings.Repeat("█", fill) + strings.Repeat("·", barWidth-fill)

					// Top line: right
					top := " " + right
					dwTop := displayWidth(top)

					if dwTop < termW {
						top = padToCellsRight(top, termW)
					} else if dwTop > termW {
						top = truncateToCells(top, termW)
					}

					// Bottom line: left + bar
					bottom := " " + left + " " + bar
					dwBottom := displayWidth(bottom)
					if dwBottom < termW {
						bottom = padToCellsRight(bottom, termW)
					} else if dwBottom > termW {
						bottom = truncateToCells(bottom, termW)
					}

					// Draw two lines pinned to the bottom; fallback to one line if height < 2
					if termH >= 2 {
						fmt.Printf("\x1b[s\x1b[%d;1H\x1b[2K%s\x1b[%d;1H\x1b[2K%s\x1b[u", termH-1, top, termH, bottom)
					} else {
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

					t := atomic.LoadInt64(&total)
					m := atomic.LoadInt64(&matched)
					mm := atomic.LoadInt64(&mismatched)
					he := atomic.LoadInt64(&httpErrs)
					ab := atomic.LoadInt64(&aborted)
					sk := atomic.LoadInt64(&skipped)
					bf := atomic.LoadInt64(&toleratedBF)
					tls := atomic.LoadInt64(&totalLatencyNs)
					mn := time.Duration(atomic.LoadInt64(&minLatencyNs))
					mx := time.Duration(atomic.LoadInt64(&maxLatencyNs))

					delta := t - prevTotal
					rps := float64(delta) / dt
					var avg time.Duration

					if t > 0 {
						avg = time.Duration(tls / t)
					}

					elapsed := now.Sub(start)
					p50 := percentileFromBuckets(0.50)
					p90 := percentileFromBuckets(0.90)
					p99 := percentileFromBuckets(0.99)

					// Include current target RPS and concurrency
					trps := getTargetRPS()

					concVal := atomic.LoadInt64(&desiredConc)
					if concVal <= 0 {
						concVal = int64(*concurrency)
					}

					var trackRatio float64
					if trps > 0 {
						trackRatio = rps / trps
						if trackRatio > 1 {
							trackRatio = 1
						}

						if trackRatio < 0 {
							trackRatio = 0
						}
					}

					fmt.Printf("\n[progress %s] total=%d matched=%d mismatched=%d http_errors=%d aborted=%d skipped=%d tolerated_bf=%d rps=%.2f target_rps=%f track_ratio=%.2f concurrency=%d avg_latency=%s min_latency=%s max_latency=%s p50=%s p90=%s p99=%s\n",
						elapsed.Truncate(time.Second), t, m, mm, he, ab, sk, bf, rps, trps, trackRatio, concVal, avg, mn, mx, p50, p90, p99,
					)

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

		// Enqueue jobs
		for k := 0; k < total; k++ {
			jobs <- job{rowIndex: i, groupID: gid, groupN: total}
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

	// Prepare pacer (RPS limiter)
	var pacer *Pacer
	if *autoMode {
		startR := *autoStartRPS
		if startR <= 0 {
			startR = 1
		}

		pacer = NewPacer(startR)
		setTargetRPS(startR)
	} else if *rps > 0 {
		pacer = NewPacer(*rps)
		setTargetRPS(*rps)
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
			wg.Add(*concurrency)
			for i := 0; i < *concurrency; i++ {
				go worker()
			}
		}

		// Start adaptive controller if enabled (after workers are spawned)
		if *autoMode {
			startController := func(durationMode bool) {
				// Control cadence: at most every 5s to ramp faster regardless of progress interval
				ctrlEvery := *progressEvery
				if ctrlEvery <= 0 || ctrlEvery > 5*time.Second {
					ctrlEvery = 5 * time.Second
				}

				maxR := *autoMaxRPS
				if maxR < 0 {
					maxR = 0
				}

				maxC := *autoMaxConc
				if maxC <= 0 {
					maxC = *concurrency
				}

				currR := *autoStartRPS
				if currR <= 0 {
					currR = 1
				}

				if pacer != nil {
					pacer.SetRPS(currR)
					setTargetRPS(currR)
				}

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

								if pacer != nil {
									if maxR > 0 && currR > maxR {
										currR = maxR
									}

									pacer.SetRPS(currR)
									setTargetRPS(currR)
								}

								continue
							}

							p95 := percentileFromBuckets(0.95)
							errPct := 100 * float64(de) / float64(max(1, dt))

							violate := errPct > *autoMaxErr || p95 > time.Duration(*autoTargetP95)*time.Millisecond
							if violate {
								currR = math.Max(1, currR*(*autoBackoff))
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

								// Reset plateau state on violation
								plateauStreak = 0
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
											// No freeze after explicit backoff
										default: // freeze
											if *autoPlateauCooldown > 0 {
												freezeWins = *autoPlateauCooldown
											} else {
												freezeWins = 1
											}
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
											case "shift":
												// Pause RPS increases; increase concurrency once (if allowed)
												if *autoPlateauCooldown > 0 {
													freezeRPSWins = *autoPlateauCooldown
												} else {
													freezeRPSWins = 1
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
											default: // freeze
												if *autoPlateauCooldown > 0 {
													freezeWins = *autoPlateauCooldown
												} else {
													freezeWins = 1
												}
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
							}

							if pacer != nil {
								if maxR > 0 && currR > maxR {
									currR = maxR
								}

								pacer.SetRPS(currR)
								setTargetRPS(currR)
							}
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

			if time.Now().After(deadline) {
				break
			}

			if tick != nil {
				select {
				case <-tick:
				case <-ctx.Done():
					break outerLoop
				}
			}

			enqueueParallelGroup(i)
		}

		close(jobs)
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

			wg.Add(*concurrency)
			for i := 0; i < *concurrency; i++ {
				go worker()
			}

			if *autoMode && cycle == 1 {
				// Start controller once for loops mode (RPS only)
				startController := func() {
					// Faster cadence: at most every 5s
					ctrlEvery := *progressEvery
					if ctrlEvery <= 0 || ctrlEvery > 5*time.Second {
						ctrlEvery = time.Second * 5
					}

					maxR := *autoMaxRPS
					if maxR < 0 {
						maxR = 0
					}

					currR := *autoStartRPS
					if currR <= 0 {
						currR = 1
					}

					if pacer != nil {
						pacer.SetRPS(currR)
						setTargetRPS(currR)
					}

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
										pacer.SetRPS(currR)
										setTargetRPS(currR)
									}

									continue
								}

								p95 := percentileFromBuckets(0.95)
								errPct := 100 * float64(de) / float64(max(1, dt))

								violate := errPct > *autoMaxErr || p95 > time.Duration(*autoTargetP95)*time.Millisecond
								if violate {
									currR = math.Max(1, currR*(*autoBackoff))
									plateauStreak = 0
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
											default: // freeze
												if *autoPlateauCooldown > 0 {
													freezeWins = *autoPlateauCooldown
												} else {
													freezeWins = 1
												}
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
								}

								if pacer != nil {
									if maxR > 0 && currR > maxR {
										currR = maxR
									}

									pacer.SetRPS(currR)
									setTargetRPS(currR)
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
					close(jobs)
					wg.Wait()

					break outerCycles
				}

				if tick != nil {
					select {
					case <-tick:
					case <-ctx.Done():
						close(jobs)
						wg.Wait()

						break outerCycles
					}
				}

				enqueueParallelGroup(i)
			}

			close(jobs)
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
			}
		}

		if pacer != nil {
			pacer.Stop()
		}
	}

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

		fmt.Printf("final_target_rps=%f final_concurrency=%d focus=%s\n", trps, concVal, *autoFocus)
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
