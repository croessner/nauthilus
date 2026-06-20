package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// MetricsPoller periodically fetches Prometheus metrics from the server.
type MetricsPoller struct {
	client   *http.Client
	url      string
	header   http.Header
	interval time.Duration
	line     atomic.Value
	lastDrop map[string]float64
	lastRepl map[string]float64
	regexes  []*regexp.Regexp
}

// NewMetricsPoller provides the exported NewMetricsPoller function.
func NewMetricsPoller(client *http.Client, endpoint string, header http.Header, interval time.Duration) *MetricsPoller {
	if interval <= 0 {
		interval = 5 * time.Second
	}

	p := &MetricsPoller{
		client:   client,
		url:      deriveMetricsURL(endpoint),
		header:   header,
		interval: interval,
		lastDrop: make(map[string]float64),
		lastRepl: make(map[string]float64),
	}

	p.line.Store("[metrics: collecting…]")

	p.regexes = []*regexp.Regexp{
		regexp.MustCompile(`^lua_queue_depth\b`),
		regexp.MustCompile(`^lua_queue_wait_seconds_(sum|count)\b`),
		regexp.MustCompile(`^lua_queue_dropped_total\b`),
		regexp.MustCompile(`^lua_vm_in_use\b`),
		regexp.MustCompile(`^lua_vm_replaced_total\b`),
	}

	return p
}

// Run provides the exported Run method.
func (p *MetricsPoller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			line := p.fetchAndFormat(ctx)
			if line == "" {
				line = "[metrics: n/a]"
			}

			p.line.Store(line)
		}
	}
}

// GetLine provides the exported GetLine method.
func (p *MetricsPoller) GetLine() string {
	val := p.line.Load()
	if s, ok := val.(string); ok {
		return s
	}

	return ""
}

func (p *MetricsPoller) fetchAndFormat(ctx context.Context) string {
	if p.url == "" {
		return ""
	}

	body, ok := p.fetchMetricsBody(ctx)
	if !ok {
		return ""
	}
	defer func() { _ = body.Close() }()

	metrics := p.collectLuaMetrics(body)

	return p.formatLuaMetrics(metrics)
}

// fetchMetricsBody performs one metrics request and returns a readable response body.
func (p *MetricsPoller) fetchMetricsBody(ctx context.Context) (io.ReadCloser, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, false
	}

	for k, v := range p.header {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	req.Header.Set("Accept", "text/plain; version=0.0.4")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, false
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()

		return nil, false
	}

	return resp.Body, true
}

type luaMetricsSnapshot struct {
	depthByBackend   map[string]float64
	droppedByBackend map[string]float64
	vmInUseByKey     map[string]float64
	replacedByKey    map[string]float64
	waitSum          float64
	waitCount        float64
}

type metricKV struct {
	key   string
	value float64
}

// collectLuaMetrics scans Prometheus samples relevant to Lua runtime status.
func (p *MetricsPoller) collectLuaMetrics(reader io.Reader) luaMetricsSnapshot {
	metrics := luaMetricsSnapshot{
		depthByBackend:   map[string]float64{},
		droppedByBackend: map[string]float64{},
		vmInUseByKey:     map[string]float64{},
		replacedByKey:    map[string]float64{},
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		name, labels, value, ok := p.parseMetricSample(scanner.Text())
		if !ok {
			continue
		}

		metrics.add(name, labels, value)
	}

	return metrics
}

// parseMetricSample parses one Prometheus text sample selected by the poller regexes.
func (p *MetricsPoller) parseMetricSample(line string) (string, map[string]string, float64, bool) {
	if line == "" || line[0] == '#' || !p.matchesMetric(line) {
		return "", nil, 0, false
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", nil, 0, false
	}

	val, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return "", nil, 0, false
	}

	name, labels := splitMetricHead(parts[0])

	return name, labels, val, true
}

// matchesMetric reports whether a Prometheus line has one of the tracked metric names.
func (p *MetricsPoller) matchesMetric(line string) bool {
	for _, re := range p.regexes {
		if re.MatchString(line) {
			return true
		}
	}

	return false
}

// splitMetricHead separates a metric name from optional labels.
func splitMetricHead(head string) (string, map[string]string) {
	if i := strings.IndexByte(head, '{'); i >= 0 {
		j := strings.LastIndexByte(head, '}')
		if j > i {
			return head[:i], parseLabels(head[i : j+1])
		}
	}

	return head, map[string]string{}
}

// add stores one selected metric sample in the snapshot.
func (m *luaMetricsSnapshot) add(name string, labels map[string]string, val float64) {
	switch name {
	case "lua_queue_depth":
		m.depthByBackend[labels["backend"]] += val
	case "lua_queue_wait_seconds_sum":
		m.waitSum += val
	case "lua_queue_wait_seconds_count":
		m.waitCount += val
	case "lua_queue_dropped_total":
		m.droppedByBackend[labels["backend"]] = val
	case "lua_vm_in_use":
		m.vmInUseByKey[labels["key"]] = val
	case "lua_vm_replaced_total":
		m.replacedByKey[labels["key"]] = val
	}
}

// formatLuaMetrics renders the latest Lua runtime metrics as a compact status line.
func (p *MetricsPoller) formatLuaMetrics(metrics luaMetricsSnapshot) string {
	var sb strings.Builder

	writeTopMetrics(&sb, "[lua qDepth: ", pickTopMetrics(metrics.depthByBackend, 3))
	fmt.Fprintf(&sb, " | total=%.0f] ", sumMetricValues(metrics.depthByBackend))
	sb.WriteString("[qWait(avg)=")
	fmt.Fprintf(&sb, "%.1fms] ", averageWaitMs(metrics))
	sb.WriteString("[dropped(\u0394)=")
	fmt.Fprintf(&sb, "%.0f] ", p.counterDeltaTotal(metrics.droppedByBackend, p.lastDrop))
	sb.WriteString("[vmRepl(\u0394)=")
	fmt.Fprintf(&sb, "%.0f] ", p.counterDeltaTotal(metrics.replacedByKey, p.lastRepl))
	writeTopMetrics(&sb, "[vmInUse: ", pickTopMetrics(metrics.vmInUseByKey, 3))
	fmt.Fprintf(&sb, " | total=%.0f]", sumMetricValues(metrics.vmInUseByKey))

	return sb.String()
}

// pickTopMetrics returns the highest positive metric values.
func pickTopMetrics(metrics map[string]float64, n int) []metricKV {
	values := make([]metricKV, 0, len(metrics))

	for key, value := range metrics {
		if value > 0 {
			values = append(values, metricKV{key: key, value: value})
		}
	}

	sort.Slice(values, func(i, j int) bool { return values[i].value > values[j].value })

	if n > 0 && len(values) > n {
		return values[:n]
	}

	return values
}

// sumMetricValues returns the sum of all values in a metric map.
func sumMetricValues(metrics map[string]float64) float64 {
	var total float64

	for _, value := range metrics {
		total += value
	}

	return total
}

// averageWaitMs returns the average queue wait in milliseconds.
func averageWaitMs(metrics luaMetricsSnapshot) float64 {
	if metrics.waitCount <= 0 {
		return 0
	}

	return (metrics.waitSum / metrics.waitCount) * 1000.0
}

// counterDeltaTotal returns the monotonic counter increase and refreshes prior values.
func (p *MetricsPoller) counterDeltaTotal(current map[string]float64, previous map[string]float64) float64 {
	var total float64

	for key, value := range current {
		prev := previous[key]
		if value >= prev {
			total += value - prev
		}

		previous[key] = value
	}

	return total
}

// writeTopMetrics writes a compact key=value list or a placeholder.
func writeTopMetrics(sb *strings.Builder, prefix string, values []metricKV) {
	sb.WriteString(prefix)

	if len(values) == 0 {
		sb.WriteString("-")

		return
	}

	for i, kv := range values {
		if i > 0 {
			sb.WriteString(",")
		}

		fmt.Fprintf(sb, "%s=%.0f", kv.key, kv.value)
	}
}

func deriveMetricsURL(apiURL string) string {
	u, err := url.ParseRequestURI(apiURL)
	if err != nil {
		return ""
	}
	// /api/v1/auth/json -> /metrics
	path := u.Path
	if before, _, ok := strings.Cut(path, "/api/"); ok {
		u.Path = before + "/metrics"
	} else {
		u.Path = "/metrics"
	}

	return u.String()
}

func parseLabels(s string) map[string]string {
	s = strings.Trim(s, "{}")
	if s == "" {
		return map[string]string{}
	}

	parser := &labelParser{labels: map[string]string{}}
	for _, r := range s {
		parser.consume(r)
	}

	parser.flush()

	return parser.labels
}

type labelParser struct {
	labels  map[string]string
	key     string
	value   string
	inValue bool
	escaped bool
}

// consume applies one rune from a Prometheus label set.
func (p *labelParser) consume(r rune) {
	if p.escaped {
		p.value += string(r)
		p.escaped = false

		return
	}

	if r == '\\' {
		p.escaped = true

		return
	}

	if r == '"' {
		p.inValue = !p.inValue

		return
	}

	if p.inValue {
		p.value += string(r)

		return
	}

	p.consumeKeyRune(r)
}

// consumeKeyRune applies a rune while parsing the label key side.
func (p *labelParser) consumeKeyRune(r rune) {
	switch {
	case r == ',':
		p.flush()
	case r == '=':
		return
	case unicode.IsSpace(r):
		return
	default:
		p.key += string(r)
	}
}

// flush stores the current key/value pair and resets parser state.
func (p *labelParser) flush() {
	if p.key != "" {
		p.labels[p.key] = p.value
	}

	p.key = ""
	p.value = ""
	p.inValue = false
	p.escaped = false
}
