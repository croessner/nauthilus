package engine

import (
	"bufio"
	"context"
	"fmt"
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return ""
	}

	for k, v := range p.header {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
	req.Header.Set("Accept", "text/plain; version=0.0.4")

	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	depthByBackend := map[string]float64{}
	var waitSum, waitCount float64
	droppedByBackend := map[string]float64{}
	vmInUseByKey := map[string]float64{}
	replacedByKey := map[string]float64{}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		matched := false
		for _, re := range p.regexes {
			if re.MatchString(line) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		head := parts[0]
		val, err := strconv.ParseFloat(parts[1], 64)
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

	type kv struct {
		k string
		v float64
	}

	pickTop := func(m map[string]float64, n int) []kv {
		a := make([]kv, 0, len(m))
		for k, v := range m {
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

	droppedDeltaTotal := 0.0
	for b, cur := range droppedByBackend {
		prev := p.lastDrop[b]
		if cur >= prev {
			droppedDeltaTotal += (cur - prev)
		}
		p.lastDrop[b] = cur
	}

	replacedDeltaTotal := 0.0
	for k, cur := range replacedByKey {
		prev := p.lastRepl[k]
		if cur >= prev {
			replacedDeltaTotal += cur - prev
		}
		p.lastRepl[k] = cur
	}

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

	sb.WriteString(fmt.Sprintf(" | total=%.0f] ", depthTotal))
	sb.WriteString("[qWait(avg)=")
	sb.WriteString(fmt.Sprintf("%.1fms] ", avgWaitMs))
	sb.WriteString("[dropped(\u0394)=")
	sb.WriteString(fmt.Sprintf("%.0f] ", droppedDeltaTotal))
	sb.WriteString("[vmRepl(\u0394)=")
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
	sb.WriteString(fmt.Sprintf(" | total=%.0f]", vmInUseTotal))

	return sb.String()
}

func deriveMetricsURL(apiURL string) string {
	u, err := url.ParseRequestURI(apiURL)
	if err != nil {
		return ""
	}
	// /api/v1/auth/json -> /metrics
	path := u.Path
	if idx := strings.Index(path, "/api/"); idx != -1 {
		u.Path = path[:idx] + "/metrics"
	} else {
		u.Path = "/metrics"
	}
	return u.String()
}

func parseLabels(s string) map[string]string {
	m := make(map[string]string)
	s = strings.Trim(s, "{}")
	if s == "" {
		return m
	}

	var key, val string
	var inVal bool
	var escaped bool

	add := func() {
		if key != "" {
			m[key] = val
		}
		key, val = "", ""
		inVal, escaped = false, false
	}

	for _, r := range s {
		if escaped {
			val += string(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inVal = !inVal
			continue
		}
		if !inVal {
			if r == ',' {
				add()
				continue
			}
			if r == '=' {
				continue
			}
			if unicode.IsSpace(r) {
				continue
			}
			key += string(r)
			continue
		}
		val += string(r)
	}

	if key != "" {
		add()
	}

	return m
}
