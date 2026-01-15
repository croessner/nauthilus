package engine

import (
	"fmt"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/mattn/go-runewidth"
	"golang.org/x/sys/unix"
)

func IsTTY() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func TermSize() (w, h int) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil || ws.Col == 0 || ws.Row == 0 {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}

func displayWidth(s string) int { return runewidth.StringWidth(s) }

func truncateToCells(s string, max int) string { return runewidth.Truncate(s, max, "") }

func padToCellsRight(s string, w int) string { return runewidth.FillRight(s, w) }

const (
	AnsiReset = "\x1b[0m"
	AnsiDim   = "\x1b[2m"
	AnsiBold  = "\x1b[1m"

	FgRed     = "\x1b[91m"
	FgGreen   = "\x1b[92m"
	FgYellow  = "\x1b[93m"
	FgBlue    = "\x1b[94m"
	FgMagenta = "\x1b[95m"
	FgCyan    = "\x1b[96m"
	FgWhite   = "\x1b[97m"
)

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
	StyleBold, StyleFaint, StyleItalic                                    colorStyle
	StyleRed, StyleGreen, StyleYellow, StyleBlue, StyleMagenta, StyleCyan colorStyle
)

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

func CalcErrorRatePct(s Stats) float64 {
	if s.Total == 0 {
		return 0
	}
	errs := s.HttpErrs + s.Aborted
	return (float64(errs) / float64(s.Total)) * 100
}

func Clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

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
	for i := 0; i < len(buckets); i++ {
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
	for i := 0; i < cols; i++ {
		var sum int64
		for j := 0; j < bucketSpan; j++ {
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

func PrintLatencyHistogram(stats Stats, buckets []atomic.Int64, overflow int64) {
	height := 10
	dataStart, dataEnd, ok := findNonZeroRange(buckets)
	if !ok {
		fmt.Println("[hist] no data")
		return
	}

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

	termW, _ := TermSize()
	gutter := 2
	provisionalLabel := 4
	usable := termW - provisionalLabel - gutter
	if usable < 20 {
		usable = 20
	}
	if span < usable {
		usable = span
	}

	bucketSpan := (span + usable - 1) / usable
	cols := (span + bucketSpan - 1) / bucketSpan
	counts, maxC := computeHistogramCounts(buckets, start, end, bucketSpan, cols)

	if maxC == 0 {
		fmt.Println("[hist] all-zero buckets")
		return
	}

	labelWidth := len(humanCount(maxC))
	if labelWidth < 4 {
		labelWidth = 4
	}

	// Recompute for exact fit
	usable = termW - labelWidth - gutter
	if usable < 20 {
		usable = 20
	}
	if span < usable {
		usable = span
	}
	bucketSpan = (span + usable - 1) / usable
	cols = (span + bucketSpan - 1) / bucketSpan
	counts, maxC = computeHistogramCounts(buckets, start, end, bucketSpan, cols)

	fmt.Printf("Latency histogram  bins=%d height=%d\n", cols, height)

	drawCols := cols
	if drawCols < usable {
		drawCols = usable
	}

	colWidth := drawCols / cols
	if colWidth < 1 {
		colWidth = 1
	}
	rem := drawCols - colWidth*cols

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

	fmt.Printf("%*s ", labelWidth, "count")
	fmt.Println(StyleBlue.S("↑"))

	for row := height; row >= 1; row-- {
		thr := int64(math.Round(float64(maxC) * float64(row) / float64(height)))
		fmt.Printf("%*s ", labelWidth, humanCount(thr))
		fmt.Print(StyleBlue.S("│"))
		for i := 0; i < cols; i++ {
			h := int(math.Round(float64(counts[i]) / float64(maxC) * float64(height)))
			w := binWidths[i]
			if h >= row {
				fmt.Print(strings.Repeat("█", w))
			} else {
				fmt.Print(strings.Repeat(" ", w))
			}
		}
		fmt.Println()
	}

	fmt.Printf("%*s ", labelWidth, "")
	fmt.Print(StyleBlue.S("└"))

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
			fmt.Print(StyleBlue.S("┬"))
		} else {
			fmt.Print(StyleBlue.S("─"))
		}
	}
	fmt.Println()

	// Markers (p50, p90, p99)
	fmt.Printf("%*s  ", labelWidth, "")
	line := make([]rune, drawCols)
	for i := range line {
		line[i] = ' '
	}
	place := func(ms time.Duration, text string) {
		mms := int(ms / time.Millisecond)
		var bin int
		if mms < start {
			bin = 0
		} else if mms > end {
			bin = cols - 1
		} else {
			bin = (mms - start) / bucketSpan
		}
		if bin < 0 {
			bin = 0
		}
		if bin >= cols {
			bin = cols - 1
		}
		s := binStarts[bin]
		w := binWidths[bin]
		t := []rune(text)
		pos := s + (w-len(t))/2
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
	place(stats.P50, "p50")
	place(stats.P90, "p90")
	place(stats.P99, "p99")
	fmt.Println(string(line))

	fmt.Printf("%*s  ", labelWidth, "ms")
	last := 0
	nTicks := len(tickPos)
	for i, x := range tickPos {
		msVal := dataStart + int(math.Round(float64(x)/float64(drawCols-1)*float64(dataSpan-1)))
		if x == drawCols-1 {
			msVal = dataEnd
		}
		label := humanMs(msVal)
		pos := x
		if i == nTicks-1 {
			pos = x - len(label) + 1
		} else if i > 0 {
			pos = x - len(label)/2
		}
		if pos < last {
			continue
		}
		padding := pos - last
		fmt.Printf("%*s%s", padding, "", label)
		last = pos + len(label)
	}
	fmt.Println()
}
