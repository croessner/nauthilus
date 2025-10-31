package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigFastest

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

// Erlaubte JSON-Schlüssel gemäß server/model/authdto/json_request.go
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
		csvPath       = flag.String("csv", "client/logins.csv", "CSV file path")
		endpoint      = flag.String("url", "http://localhost:8080/api/v1/auth/json", "Auth endpoint URL")
		method        = flag.String("method", "POST", "HTTP method")
		concurrency   = flag.Int("concurrency", 16, "Concurrent workers")
		rps           = flag.Float64("rps", 0, "Global rate limit (0=unlimited)")
		jitterMs      = flag.Int("jitter-ms", 0, "Random sleep 0..N ms before each request")
		delayMs       = flag.Int("delay-ms", 0, "Fixed delay per item in worker")
		timeoutMs     = flag.Int("timeout-ms", 5000, "HTTP timeout")
		maxRows       = flag.Int("max", 0, "Limit number of rows (0=all)")
		shuffle       = flag.Bool("shuffle", true, "Shuffle rows before sending")
		headersList   = flag.String("headers", "Content-Type: application/json", "Extra headers, separated by '||'")
		basicAuth     = flag.String("basic-auth", "", "HTTP Basic-Auth credentials in format username:password")
		okStatus      = flag.Int("ok-status", 200, "HTTP status indicating success when not using JSON flag")
		useJSONFlag   = flag.Bool("json-ok", true, "Expect JSON {ok:true|false} in response")
		verbose       = flag.Bool("v", false, "Verbose output")
		genCSV        = flag.Bool("generate-csv", false, "Generate a CSV at --csv path and exit")
		genCount      = flag.Int("generate-count", 10000, "Number of rows to generate when --generate-csv is set")
		genCIDRProb   = flag.Float64("generate-cidr-prob", 0.0, "Probability (0..1) that generated IPs are taken from the same CIDR block")
		genCIDRPrefix = flag.Int("generate-cidr-prefix", 24, "CIDR prefix length (8..30) of the shared block for IP grouping")
		csvDelim      = flag.String("csv-delim", "", "CSV delimiter override: ',', ';', 'tab'; empty=auto-detect")
		csvDebug      = flag.Bool("csv-debug", false, "Print detected CSV headers and first row")
		loops         = flag.Int("loops", 1, "Number of cycles to run over the CSV")
		runFor        = flag.Duration("duration", 0, "Total duration to run the test (e.g. 5m). CSV rows will loop until time elapses")
		maxPar        = flag.Int("max-parallel", 1, "Max parallel requests per item (1=off)")
		parProb       = flag.Float64("parallel-prob", 0.0, "Probability (0..1) that an item is parallelized")
		abortProb     = flag.Float64("abort-prob", 0.0, "Probability (0..1) to abort/cancel a request (simulates connection drop)")
		progressEvery = flag.Duration("progress-interval", time.Minute, "Progress report interval (e.g. 30s, 1m)")
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

	for i := range rows {
		usernames[i] = strings.TrimSpace(resolveUsername(rows[i].Fields))
		clientIPs[i] = strings.TrimSpace(rows[i].Fields["client_ip"])
		payload := makePayload(rows[i].Fields)
		bb, _ := json.Marshal(payload)
		bodies[i] = bb
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
	client := &http.Client{Timeout: time.Duration(*timeoutMs) * time.Millisecond, Transport: transport}

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

	// Periodic progress reporter (only if interval > 0)
	if *progressEvery > 0 {
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

					// periodical RPS since last report
					delta := t - prevTotal
					rps := float64(delta) / dt

					var avg time.Duration
					if t > 0 {
						avg = time.Duration(tls / t)
					}

					elapsed := now.Sub(start)
					fmt.Printf("\n[progress %s] total=%d matched=%d mismatched=%d http_errors=%d aborted=%d skipped=%d tolerated_bf=%d rps=%.2f avg_latency=%s min_latency=%s max_latency=%s\n",
						elapsed.Truncate(time.Second), t, m, mm, he, ab, sk, bf, rps, avg, mn, mx,
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
	jobs := make(chan int, *concurrency)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()

		// Per-worker reusable buffer to drain response bodies without per-request allocations
		buf := make([]byte, 32<<10)

		for idx := range jobs {
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

			req.ContentLength = int64(len(bb))

			if clientIP != "" {
				req.Header.Set("X-Forwarded-For", clientIP)
			}

			ts := time.Now()
			resp, err := client.Do(req)
			lat := time.Since(ts)

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
				if *useJSONFlag {
					// Decode into a concrete type (no interface boxing)
					var jr struct {
						OK bool `json:"ok"`
					}

					_ = json.NewDecoder(resp.Body).Decode(&jr)
					gotOK = jr.OK
				} else {
					gotOK = resp.StatusCode == *okStatus
				}

				// Drain body with per-worker buffer to keep connections reusable without per-request allocs
				io.CopyBuffer(io.Discard, resp.Body, buf)

				// Count HTTP status code
				code := resp.StatusCode
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
		// Always enqueue at least one job
		jobs <- i

		// Feature off?
		if *maxPar <= 1 || *parProb <= 0 {
			return
		}

		// Decide whether to parallelize this item
		if rand.Float64() >= *parProb {
			return
		}

		// Number of extra parallel jobs: 0..(maxPar-1)
		extra := rand.IntN(*maxPar)

		for k := 0; k < extra; k++ {
			jobs <- i
		}
	}

	// Duration mode: loop over CSV until time elapses
	if *runFor > 0 {
		var tick <-chan time.Time
		var t *time.Ticker

		if *rps > 0 {
			interval := time.Duration(float64(time.Second) / *rps)
			t = time.NewTicker(interval)
			tick = t.C
		}

		wg.Add(*concurrency)
		for i := 0; i < *concurrency; i++ {
			go worker()
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

		if t != nil {
			t.Stop()
		}
	} else {
		// Legacy loops mode (kept for backward compatibility)
	outerCycles:
		for cycle := 1; cycle <= *loops; cycle++ {
			// Per-cycle rate limiter
			var tick <-chan time.Time
			var t *time.Ticker

			if *rps > 0 {
				interval := time.Duration(float64(time.Second) / *rps)
				t = time.NewTicker(interval)
				tick = t.C
			}

			wg.Add(*concurrency)
			for i := 0; i < *concurrency; i++ {
				go worker()
			}

			for i := range rows {
				if atomic.LoadInt32(&stopFlag) == 1 {
					close(jobs)
					wg.Wait()

					if t != nil {
						t.Stop()
					}

					break outerCycles
				}

				if tick != nil {
					select {
					case <-tick:
					case <-ctx.Done():
						close(jobs)
						wg.Wait()

						if t != nil {
							t.Stop()
						}

						break outerCycles
					}
				}

				enqueueParallelGroup(i)
			}

			close(jobs)
			wg.Wait()

			if t != nil {
				t.Stop()
			}

			// Recreate jobs channel for next cycle
			if cycle != *loops {
				jobs = make(chan int, *concurrency)
			}
		}
	}

	// Stop progress reporter
	cancel()

	dur := time.Since(start)

	fmt.Printf("\nDone in %s\n", dur)
	fmt.Printf("total=%d matched=%d mismatched=%d http_errors=%d aborted=%d skipped=%d tolerated_bf=%d\n", total, matched, mismatched, httpErrs, aborted, skipped, toleratedBF)

	if dur > 0 {
		fmt.Printf("throughput=%.2f req/s\n", float64(total)/dur.Seconds())
	}

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
	}

	// Print HTTP status codes summary (code, count)
	fmt.Println("http_status_counts:")
	for code, cnt := range statusCounts {
		if cnt != 0 {
			fmt.Printf("  %d: %d\n", code, cnt)
		}
	}
}
