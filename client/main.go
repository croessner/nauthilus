package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
func generateCSV(path string, total int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20)

	defer w.Flush()

	// Full header as used in the example CSV and accepted by the client
	fmt.Fprintln(w, "username,password,client_ip,expected_ok,user_agent,protocol,method,ssl,ssl_protocol,ssl_cipher,ssl_client_verify,ssl_client_cn")

	protocols := []string{"imap", "smtp", "pop3", "http"}
	methods := []string{"PLAIN", "LOGIN"}
	sslProtocols := []string{"TLSv1.2", "TLSv1.3"}
	sslCiphers := []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"}

	for i := 1; i <= total; i++ {
		username := fmt.Sprintf("user%05d", i)
		password := fmt.Sprintf("pw%05d", i)
		ipOctet := ((i - 1) % 254) + 1
		clientIP := fmt.Sprintf("198.51.100.%d", ipOctet)

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
		csvPath     = flag.String("csv", "client/logins.csv", "CSV file path")
		endpoint    = flag.String("url", "http://localhost:8080/api/v1/auth/json", "Auth endpoint URL")
		method      = flag.String("method", "POST", "HTTP method")
		concurrency = flag.Int("concurrency", 16, "Concurrent workers")
		rps         = flag.Float64("rps", 0, "Global rate limit (0=unlimited)")
		jitterMs    = flag.Int("jitter-ms", 0, "Random sleep 0..N ms before each request")
		delayMs     = flag.Int("delay-ms", 0, "Fixed delay per item in worker")
		timeoutMs   = flag.Int("timeout-ms", 5000, "HTTP timeout")
		maxRows     = flag.Int("max", 0, "Limit number of rows (0=all)")
		shuffle     = flag.Bool("shuffle", true, "Shuffle rows before sending")
		headersList = flag.String("headers", "Content-Type: application/json", "Extra headers, separated by '||'")
		okStatus    = flag.Int("ok-status", 200, "HTTP status indicating success when not using JSON flag")
		useJSONFlag = flag.Bool("json-ok", true, "Expect JSON {ok:true|false} in response")
		verbose     = flag.Bool("v", false, "Verbose output")
		genCSV      = flag.Bool("generate-csv", false, "Generate a CSV at --csv path and exit")
		genCount    = flag.Int("generate-count", 10000, "Number of rows to generate when --generate-csv is set")
		csvDelim    = flag.String("csv-delim", "", "CSV delimiter override: ',', ';', 'tab'; empty=auto-detect")
		csvDebug    = flag.Bool("csv-debug", false, "Print detected CSV headers and first row")
		loops       = flag.Int("loops", 1, "Number of cycles to run over the CSV")
		runFor      = flag.Duration("duration", 0, "Total duration to run the test (e.g. 5m). CSV rows will loop until time elapses")
	)

	flag.Parse()

	// Generation mode: create synthetic CSV and exit
	if *genCSV {
		if err := generateCSV(*csvPath, *genCount); err != nil {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var total, matched, mismatched, httpErrs int64
	var skipped int64
	var totalLatencyNs int64
	start := time.Now()

	// Worker function shared by both modes
	jobs := make(chan int, len(rows))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()

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

			req, _ := http.NewRequestWithContext(ctx, *method, *endpoint, bytes.NewReader(bb))

			// clone base headers to avoid data race across workers
			req.Header = baseHeader.Clone()
			req.ContentLength = int64(len(bb))

			if clientIP != "" {
				req.Header.Set("X-Forwarded-For", clientIP)
			}

			ts := time.Now()
			resp, err := client.Do(req)
			lat := time.Since(ts)
			atomic.AddInt64(&totalLatencyNs, int64(lat))

			atomic.AddInt64(&total, 1)
			if err != nil {
				atomic.AddInt64(&httpErrs, 1)
				if *verbose {
					fmt.Printf("ERR user=%s err=%v lat=%s\n", username, err, lat)
				}

				continue
			}

			func() {
				defer resp.Body.Close()
				var gotOK bool
				if *useJSONFlag {
					var jr struct {
						OK any `json:"ok"`
					}

					_ = json.NewDecoder(resp.Body).Decode(&jr)

					switch v := jr.OK.(type) {
					case bool:
						gotOK = v
					case string:
						b, _ := parseBool(v)
						gotOK = b
					case float64:
						gotOK = int(v) != 0
					}
				} else {
					gotOK = resp.StatusCode == *okStatus
				}

				io.Copy(io.Discard, resp.Body)

				if gotOK == expectedOKs[idx] {
					atomic.AddInt64(&matched, 1)

					if *verbose {
						fmt.Printf("OK user=%s status=%d lat=%s\n", username, resp.StatusCode, lat)
					}
				} else {
					atomic.AddInt64(&mismatched, 1)

					if *verbose {
						fmt.Printf("MISMATCH user=%s expected=%v got=%v status=%d lat=%s\n", username, expectedOKs[idx], gotOK, resp.StatusCode, lat)
					}
				}
			}()
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
		for i := 0; ; i = (i + 1) % len(rows) {
			if time.Now().After(deadline) {
				break
			}
			if tick != nil {
				<-tick
			}
			jobs <- i
		}

		close(jobs)
		wg.Wait()

		if t != nil {
			t.Stop()
		}
	} else {
		// Legacy loops mode (kept for backward compatibility)
		for cycle := 1; cycle <= *loops; cycle++ {
			cycleStart := time.Now()

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
				if tick != nil {
					<-tick
				}

				jobs <- i
			}

			close(jobs)
			wg.Wait()

			if t != nil {
				t.Stop()
			}

			// Recreate jobs channel for next cycle
			if cycle != *loops {
				jobs = make(chan int, len(rows))
			}
		}
	}

	dur := time.Since(start)

	fmt.Printf("\nDone in %s\n", dur)
	fmt.Printf("total=%d matched=%d mismatched=%d http_errors=%d skipped=%d\n", total, matched, mismatched, httpErrs, skipped)

	if dur > 0 {
		fmt.Printf("throughput=%.2f req/s\n", float64(total)/dur.Seconds())
	}

	if total > 0 {
		avg := time.Duration(totalLatencyNs / total)

		fmt.Printf("avg_latency=%s\n", avg)
	}
}
