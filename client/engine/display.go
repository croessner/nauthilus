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

func displayWidth(s string) int { return runewidth.StringWidth(s) }

func truncateToCells(s string, max int) string { return runewidth.Truncate(s, max, "") }

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
	termW, _ := termSize()

	labelWidth := 8
	gutter := 2
	usable := termW - labelWidth - gutter
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

	height := 10
	for r := height; r > 0; r-- {
		fmt.Printf("%*s │", labelWidth, "")
		for _, c := range counts {
			h := int(math.Ceil(float64(c) / float64(maxC) * float64(height)))
			if h >= r {
				fmt.Print("█")
			} else {
				fmt.Print(" ")
			}
		}
		fmt.Println()
	}
	// X-axis and labels simplified
	fmt.Printf("%*s └%s\n", labelWidth, "", strings.Repeat("-", cols))
	fmt.Printf("%*s %dms%*s%dms\n", labelWidth, "", start, cols-len(fmt.Sprintf("%dms", start)), "", end)
}
