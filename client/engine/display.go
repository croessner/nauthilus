package engine

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/mattn/go-runewidth"
	"golang.org/x/sys/unix"
)

// IsTTY provides the exported IsTTY function.
func IsTTY() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// TermSize provides the exported TermSize function.
func TermSize() (w, h int) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil || ws.Col == 0 || ws.Row == 0 {
		return 80, 24
	}

	return int(ws.Col), int(ws.Row)
}

func displayWidth(s string) int { return runewidth.StringWidth(s) }

func truncateToCells(s string, maxCells int) string { return runewidth.Truncate(s, maxCells, "") }

func padToCellsRight(s string, w int) string { return runewidth.FillRight(s, w) }

type colorStyle struct {
	open    string
	enabled bool
}

func (cs colorStyle) S(s string) string {
	if !cs.enabled {
		return s
	}

	return cs.open + s + "\x1b[0m"
}

var (
	// StyleFaint is an exported package value.
	StyleFaint colorStyle
	// StyleItalic is an exported package value.
	StyleItalic colorStyle
	// StyleBold is an exported package value.
	StyleBold colorStyle
	// StyleGreen is an exported package value.
	StyleGreen colorStyle
	// StyleYellow is an exported package value.
	StyleYellow colorStyle
	// StyleBlue is an exported package value.
	StyleBlue colorStyle
	// StyleMagenta is an exported package value.
	StyleMagenta colorStyle
	// StyleCyan is an exported package value.
	StyleCyan colorStyle
	// StyleRed is an exported package value.
	StyleRed colorStyle
)

// InitColorStyles provides the exported InitColorStyles function.
func InitColorStyles(enabled bool) {
	style := func(open string) colorStyle {
		return colorStyle{open: open, enabled: enabled}
	}
	StyleBold = style("\x1b[1m")
	StyleFaint = style("\x1b[2m")
	StyleItalic = style("\x1b[3m")
	StyleRed = style("\x1b[31m")
	StyleGreen = style("\x1b[32m")
	StyleYellow = style("\x1b[33m")
	StyleBlue = style("\x1b[34m")
	StyleMagenta = style("\x1b[35m")
	StyleCyan = style("\x1b[36m")
}

func humanMs(ms int) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}

	return fmt.Sprintf("%.2fs", float64(ms)/1000)
}

func humanETA(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%02dh%02dm%02ds", h, m, s)
	}

	if m > 0 {
		return fmt.Sprintf("%02dm%02ds", m, s)
	}

	return fmt.Sprintf("%ds", s)
}

func humanCount(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}

	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}

	return fmt.Sprintf("%.1fM", float64(n)/1000000)
}

// CalcErrorRatePct provides the exported CalcErrorRatePct function.
func CalcErrorRatePct(s Stats) float64 {
	if s.Total == 0 {
		return 0
	}

	errs := s.HTTPErrs + s.Aborted

	return (float64(errs) / float64(s.Total)) * 100
}

// Clamp01 provides the exported Clamp01 function.
func Clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}

	if x > 1 {
		return 1
	}

	return x
}

// SupportsUnicode provides the exported SupportsUnicode function.
func SupportsUnicode() bool {
	if os.Getenv("NO_UNICODE") != "" {
		return false
	}

	for _, env := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if strings.Contains(strings.ToUpper(os.Getenv(env)), "UTF-8") {
			return true
		}
	}

	return false
}

func findNonZeroRange(buckets []atomic.Int64) (int, int, bool) {
	start := -1
	end := -1

	for i := range buckets {
		if buckets[i].Load() > 0 {
			if start == -1 {
				start = i
			}

			end = i
		}
	}

	if start == -1 {
		return 0, 0, false
	}

	return start, end, true
}

func computeHistogramCounts(buckets []atomic.Int64, start, end, bucketSpan, cols int) ([]int64, int64) {
	counts := make([]int64, cols)

	var maxC int64

	for i := range cols {
		var sum int64

		for j := range bucketSpan {
			ms := start + i*bucketSpan + j
			if ms <= end && ms < len(buckets) {
				sum += buckets[ms].Load()
			}
		}

		counts[i] = sum
		if sum > maxC {
			maxC = sum
		}
	}

	return counts, maxC
}

type latencyHistogramRange struct {
	dataStart int
	dataEnd   int
	start     int
	end       int
	span      int
	dataSpan  int
}

type latencyHistogramLayout struct {
	counts     []int64
	binWidths  []int
	binStarts  []int
	tickPos    []int
	maxC       int64
	height     int
	labelWidth int
	bucketSpan int
	cols       int
	drawCols   int
}

// PrintLatencyHistogram provides the exported PrintLatencyHistogram function.
func PrintLatencyHistogram(stats Stats, buckets []atomic.Int64) {
	const height = 10

	histRange, ok := newLatencyHistogramRange(buckets)
	if !ok {
		fmt.Println("[hist] no data")

		return
	}

	layout, ok := newLatencyHistogramLayout(buckets, histRange, height)
	if !ok {
		fmt.Println("[hist] all-zero buckets")

		return
	}

	fmt.Printf("Latency histogram  bins=%d height=%d\n", layout.cols, layout.height)
	printHistogramRows(layout)
	printHistogramAxis(layout)
	printHistogramMarkers(stats, histRange, layout)
	printHistogramTickLabels(histRange, layout)
}

// newLatencyHistogramRange computes the padded latency range to render.
func newLatencyHistogramRange(buckets []atomic.Int64) (latencyHistogramRange, bool) {
	dataStart, dataEnd, ok := findNonZeroRange(buckets)
	if !ok {
		return latencyHistogramRange{}, false
	}

	start, end := paddedLatencyRange(dataStart, dataEnd)

	return latencyHistogramRange{
		dataStart: dataStart,
		dataEnd:   dataEnd,
		start:     start,
		end:       end,
		span:      end - start + 1,
		dataSpan:  max(dataEnd-dataStart+1, 1),
	}, true
}

// paddedLatencyRange adds visual breathing room around narrow latency ranges.
func paddedLatencyRange(dataStart int, dataEnd int) (int, int) {
	start := dataStart
	end := dataEnd
	pad := 0

	if end-start < 20 {
		pad = 2
	}

	start = max(start-pad, 0)
	end = min(end+pad, maxLatencyMs)

	return start, end
}

// newLatencyHistogramLayout computes terminal-width-dependent histogram geometry.
func newLatencyHistogramLayout(buckets []atomic.Int64, histRange latencyHistogramRange, height int) (latencyHistogramLayout, bool) {
	const (
		gutter           = 2
		provisionalLabel = 4
	)

	termW, _ := TermSize()
	usable := min(histRange.span, max(termW-provisionalLabel-gutter, 20))
	bucketSpan, cols := histogramBucketLayout(histRange.span, usable)

	_, maxC := computeHistogramCounts(buckets, histRange.start, histRange.end, bucketSpan, cols)
	if maxC == 0 {
		return latencyHistogramLayout{}, false
	}

	labelWidth := max(len(humanCount(maxC)), 4)
	usable = min(histRange.span, max(termW-labelWidth-gutter, 20))
	bucketSpan, cols = histogramBucketLayout(histRange.span, usable)
	counts, maxC := computeHistogramCounts(buckets, histRange.start, histRange.end, bucketSpan, cols)
	drawCols := max(cols, usable)
	binWidths, binStarts := histogramBinGeometry(cols, drawCols)

	return latencyHistogramLayout{
		counts:     counts,
		binWidths:  binWidths,
		binStarts:  binStarts,
		tickPos:    histogramTickPositions(drawCols),
		maxC:       maxC,
		height:     height,
		labelWidth: labelWidth,
		bucketSpan: bucketSpan,
		cols:       cols,
		drawCols:   drawCols,
	}, true
}

// histogramBucketLayout returns bucket width and column count for a span.
func histogramBucketLayout(span int, usable int) (int, int) {
	bucketSpan := (span + usable - 1) / usable
	cols := (span + bucketSpan - 1) / bucketSpan

	return bucketSpan, cols
}

// histogramBinGeometry maps histogram columns onto rendered terminal cells.
func histogramBinGeometry(cols int, drawCols int) ([]int, []int) {
	colWidth := max(drawCols/cols, 1)
	remainder := drawCols - colWidth*cols
	binWidths := make([]int, cols)
	binStarts := make([]int, cols)
	start := 0

	for i := range cols {
		width := colWidth
		if i < remainder {
			width++
		}

		binWidths[i] = width
		binStarts[i] = start
		start += width
	}

	return binWidths, binStarts
}

// histogramTickPositions returns the five evenly spaced axis tick locations.
func histogramTickPositions(drawCols int) []int {
	last := drawCols - 1

	return []int{
		0,
		int(math.Round(float64(last) * 0.25)),
		int(math.Round(float64(last) * 0.5)),
		int(math.Round(float64(last) * 0.75)),
		last,
	}
}

// printHistogramRows renders count labels and histogram bars.
func printHistogramRows(layout latencyHistogramLayout) {
	fmt.Printf("%*s ", layout.labelWidth, "count")
	fmt.Println(StyleBlue.S("↑"))

	for row := layout.height; row >= 1; row-- {
		printHistogramRow(row, layout)
	}
}

// printHistogramRow renders one horizontal bar row.
func printHistogramRow(row int, layout latencyHistogramLayout) {
	threshold := int64(math.Round(float64(layout.maxC) * float64(row) / float64(layout.height)))
	fmt.Printf("%*s ", layout.labelWidth, humanCount(threshold))
	fmt.Print(StyleBlue.S("│"))

	for i := range layout.cols {
		height := int(math.Round(float64(layout.counts[i]) / float64(layout.maxC) * float64(layout.height)))
		fmt.Print(histogramBarCell(height >= row, layout.binWidths[i]))
	}

	fmt.Println()
}

// histogramBarCell returns the filled or empty cell sequence for one histogram column.
func histogramBarCell(filled bool, width int) string {
	if filled {
		return strings.Repeat("█", width)
	}

	return strings.Repeat(" ", width)
}

// printHistogramAxis renders the x-axis baseline with tick marks.
func printHistogramAxis(layout latencyHistogramLayout) {
	fmt.Printf("%*s ", layout.labelWidth, "")
	fmt.Print(StyleBlue.S("└"))

	for x := range layout.drawCols {
		fmt.Print(StyleBlue.S(histogramAxisRune(x, layout.tickPos)))
	}

	fmt.Println()
}

// histogramAxisRune returns the axis glyph at a rendered cell.
func histogramAxisRune(x int, tickPos []int) string {
	if slices.Contains(tickPos, x) {
		return "┬"
	}

	return "─"
}

// printHistogramMarkers renders percentile labels above the tick labels.
func printHistogramMarkers(stats Stats, histRange latencyHistogramRange, layout latencyHistogramLayout) {
	fmt.Printf("%*s  ", layout.labelWidth, "")

	line := blankRuneLine(layout.drawCols)
	placeHistogramMarker(line, stats.P50, "p50", histRange, layout)
	placeHistogramMarker(line, stats.P90, "p90", histRange, layout)
	placeHistogramMarker(line, stats.P99, "p99", histRange, layout)
	fmt.Println(string(line))
}

// blankRuneLine returns a space-filled marker line.
func blankRuneLine(width int) []rune {
	line := make([]rune, width)

	for i := range line {
		line[i] = ' '
	}

	return line
}

// placeHistogramMarker writes a percentile marker into a marker line.
func placeHistogramMarker(line []rune, latency time.Duration, text string, histRange latencyHistogramRange, layout latencyHistogramLayout) {
	bin := histogramMarkerBin(latency, histRange, layout)
	start := layout.binStarts[bin]
	width := layout.binWidths[bin]
	pos := max(start+(width-len([]rune(text)))/2, 0)

	writeRunesAt(line, pos, []rune(text))
}

// histogramMarkerBin maps a latency value to a rendered histogram bin.
func histogramMarkerBin(latency time.Duration, histRange latencyHistogramRange, layout latencyHistogramLayout) int {
	ms := int(latency / time.Millisecond)
	switch {
	case ms < histRange.start:
		return 0
	case ms > histRange.end:
		return layout.cols - 1
	default:
		return min(max((ms-histRange.start)/layout.bucketSpan, 0), layout.cols-1)
	}
}

// writeRunesAt copies runes into a fixed-width line without growing it.
func writeRunesAt(line []rune, pos int, text []rune) {
	for i, r := range text {
		target := pos + i
		if target >= 0 && target < len(line) {
			line[target] = r
		}
	}
}

// printHistogramTickLabels renders millisecond labels under the axis ticks.
func printHistogramTickLabels(histRange latencyHistogramRange, layout latencyHistogramLayout) {
	fmt.Printf("%*s  ", layout.labelWidth, "ms")

	last := 0

	for i, x := range layout.tickPos {
		label := histogramTickLabel(i, x, histRange, layout)

		pos := histogramTickLabelPosition(i, x, len(label), len(layout.tickPos))
		if pos < last {
			continue
		}

		fmt.Printf("%*s%s", pos-last, "", label)
		last = pos + len(label)
	}

	fmt.Println()
}

// histogramTickLabel returns the human-readable millisecond label for a tick.
func histogramTickLabel(index int, x int, histRange latencyHistogramRange, layout latencyHistogramLayout) string {
	value := histRange.dataStart + int(math.Round(float64(x)/float64(layout.drawCols-1)*float64(histRange.dataSpan-1)))
	if index == len(layout.tickPos)-1 {
		value = histRange.dataEnd
	}

	return humanMs(value)
}

// histogramTickLabelPosition centers tick labels except for the first and last label.
func histogramTickLabelPosition(index int, x int, labelLen int, tickCount int) int {
	switch {
	case index == tickCount-1:
		return x - labelLen + 1
	case index > 0:
		return x - labelLen/2
	default:
		return x
	}
}
