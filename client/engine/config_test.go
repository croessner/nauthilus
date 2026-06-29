package engine

import (
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigFlags(t *testing.T) {
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	registerConfigTestFlags(fs, cfg)
	err := fs.Parse(configFlagArgs())

	assert.NoError(t, err)
	assertConfigFlagValues(t, cfg)
}

// registerConfigTestFlags registers all flags covered by TestConfigFlags.
func registerConfigTestFlags(fs *flag.FlagSet, cfg *Config) {
	registerCoreConfigFlags(fs, cfg)
	registerThresholdConfigFlags(fs, cfg)
	registerAutoConfigFlags(fs, cfg)
	registerRandomConfigFlags(fs, cfg)
}

// registerCoreConfigFlags registers base request, generation, and display flags.
func registerCoreConfigFlags(fs *flag.FlagSet, cfg *Config) {
	fs.StringVar(&cfg.CSVPath, "csv", cfg.CSVPath, "")
	fs.StringVar(&cfg.Endpoint, "url", cfg.Endpoint, "")
	fs.StringVar(&cfg.Method, "method", cfg.Method, "")
	fs.IntVar(&cfg.Concurrency, autoFocusConcurrency, cfg.Concurrency, "")
	fs.Float64Var(&cfg.RPS, autoFocusRPS, cfg.RPS, "")
	fs.IntVar(&cfg.JitterMs, "jitter-ms", cfg.JitterMs, "")
	fs.IntVar(&cfg.DelayMs, "delay-ms", cfg.DelayMs, "")
	fs.IntVar(&cfg.TimeoutMs, "timeout-ms", cfg.TimeoutMs, "")
	fs.IntVar(&cfg.MaxRows, "max", cfg.MaxRows, "")
	fs.BoolVar(&cfg.Shuffle, "shuffle", cfg.Shuffle, "")
	fs.StringVar(&cfg.HeadersList, "headers", cfg.HeadersList, "")
	fs.StringVar(&cfg.BasicAuth, "basic-auth", cfg.BasicAuth, "")
	fs.BoolVar(&cfg.InsecureTLS, "insecure-tls", cfg.InsecureTLS, "")
	fs.IntVar(&cfg.OKStatus, "ok-status", cfg.OKStatus, "")
	fs.BoolVar(&cfg.UseJSONFlag, "json-ok", cfg.UseJSONFlag, "")
	fs.BoolVar(&cfg.Verbose, "v", cfg.Verbose, "")
	fs.BoolVar(&cfg.GenCSV, "generate-csv", cfg.GenCSV, "")
	fs.IntVar(&cfg.GenCount, "generate-count", cfg.GenCount, "")
	fs.Float64Var(&cfg.GenCIDRProb, "generate-cidr-prob", cfg.GenCIDRProb, "")
	fs.IntVar(&cfg.GenCIDRPrefix, "generate-cidr-prefix", cfg.GenCIDRPrefix, "")
	fs.StringVar(&cfg.CSVDelim, "csv-delim", cfg.CSVDelim, "")
	fs.BoolVar(&cfg.CSVDebug, "csv-debug", cfg.CSVDebug, "")
	fs.IntVar(&cfg.Loops, "loops", cfg.Loops, "")
	fs.DurationVar(&cfg.RunFor, "duration", cfg.RunFor, "")
	fs.IntVar(&cfg.MaxParallel, "max-parallel", cfg.MaxParallel, "")
	fs.Float64Var(&cfg.ParallelProb, "parallel-prob", cfg.ParallelProb, "")
	fs.Float64Var(&cfg.AbortProb, "abort-prob", cfg.AbortProb, "")
	fs.DurationVar(&cfg.ProgressEvery, "progress-interval", cfg.ProgressEvery, "")
	fs.BoolVar(&cfg.CompareParallel, "compare-parallel", cfg.CompareParallel, "")
	fs.BoolVar(&cfg.UseIdemKey, "idempotency-key", cfg.UseIdemKey, "")
	fs.BoolVar(&cfg.ProgressBar, "progress-bar", cfg.ProgressBar, "")
	fs.StringVar(&cfg.ColorMode, "color", cfg.ColorMode, "")
}

// registerThresholdConfigFlags registers warning and critical threshold flags.
func registerThresholdConfigFlags(fs *flag.FlagSet, cfg *Config) {
	fs.IntVar(&cfg.WarnP95, "warn-p95", cfg.WarnP95, "")
	fs.IntVar(&cfg.CritP95, "crit-p95", cfg.CritP95, "")
	fs.Float64Var(&cfg.WarnErr, "warn-error-rate", cfg.WarnErr, "")
	fs.Float64Var(&cfg.CritErr, "crit-error-rate", cfg.CritErr, "")
	fs.Float64Var(&cfg.WarnTrack, "warn-track", cfg.WarnTrack, "")
	fs.Float64Var(&cfg.CritTrack, "crit-track", cfg.CritTrack, "")
	fs.IntVar(&cfg.GraceSeconds, "grace-seconds", cfg.GraceSeconds, "")
}

// registerAutoConfigFlags registers adaptive-control flags.
func registerAutoConfigFlags(fs *flag.FlagSet, cfg *Config) {
	fs.BoolVar(&cfg.AutoMode, "auto", cfg.AutoMode, "")
	fs.IntVar(&cfg.AutoTargetP95, "auto-target-p95", cfg.AutoTargetP95, "")
	fs.Float64Var(&cfg.AutoMaxRPS, "auto-max-rps", cfg.AutoMaxRPS, "")
	fs.IntVar(&cfg.AutoMaxConc, "auto-max-concurrency", cfg.AutoMaxConc, "")
	fs.Float64Var(&cfg.AutoStartRPS, "auto-start-rps", cfg.AutoStartRPS, "")
	fs.IntVar(&cfg.AutoStartConc, "auto-start-concurrency", cfg.AutoStartConc, "")
	fs.Float64Var(&cfg.AutoStepRPS, "auto-step-rps", cfg.AutoStepRPS, "")
	fs.IntVar(&cfg.AutoStepConc, "auto-step-concurrency", cfg.AutoStepConc, "")
	fs.Float64Var(&cfg.AutoBackoff, "auto-backoff", cfg.AutoBackoff, "")
	fs.Float64Var(&cfg.AutoMaxErr, "auto-max-err", cfg.AutoMaxErr, "")
	fs.IntVar(&cfg.AutoMinSample, "auto-min-sample", cfg.AutoMinSample, "")
	fs.StringVar(&cfg.AutoFocus, "auto-focus", cfg.AutoFocus, "")

	fs.BoolVar(&cfg.AutoPlateau, "auto-plateau", cfg.AutoPlateau, "")
	fs.IntVar(&cfg.AutoPlateauWindows, "auto-plateau-windows", cfg.AutoPlateauWindows, "")
	fs.Float64Var(&cfg.AutoPlateauGain, "auto-plateau-gain", cfg.AutoPlateauGain, "")
	fs.StringVar(&cfg.AutoPlateauAction, "auto-plateau-action", cfg.AutoPlateauAction, "")
	fs.IntVar(&cfg.AutoPlateauCooldown, "auto-plateau-cooldown", cfg.AutoPlateauCooldown, "")
	fs.Float64Var(&cfg.AutoPlateauTrackThreshold, "auto-plateau-track-threshold", cfg.AutoPlateauTrackThreshold, "")
	fs.IntVar(&cfg.AutoPlateauTrackWindows, "auto-plateau-track-windows", cfg.AutoPlateauTrackWindows, "")
	fs.StringVar(&cfg.AutoPlateauTrackAction, "auto-plateau-track-action", cfg.AutoPlateauTrackAction, "")
}

// registerRandomConfigFlags registers stochastic request-mutation flags.
func registerRandomConfigFlags(fs *flag.FlagSet, cfg *Config) {
	fs.BoolVar(&cfg.RandomNoAuth, "random-no-auth", cfg.RandomNoAuth, "")
	fs.Float64Var(&cfg.RandomNoAuthProb, "random-no-auth-prob", cfg.RandomNoAuthProb, "")
	fs.BoolVar(&cfg.RandomBadPass, "random-bad-pass", cfg.RandomBadPass, "")
	fs.Float64Var(&cfg.RandomBadPassProb, "random-bad-pass-prob", cfg.RandomBadPassProb, "")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "")
}

// configFlagArgs returns the complete flag argument set for TestConfigFlags.
func configFlagArgs() []string {
	args := configRequestFlagArgs()
	args = append(args, configRuntimeFlagArgs()...)
	args = append(args, configThresholdFlagArgs()...)
	args = append(args, configAutoFlagArgs()...)
	args = append(args, configRandomFlagArgs()...)

	return args
}

// configRequestFlagArgs returns request and input-related flag arguments.
func configRequestFlagArgs() []string {
	return []string{
		"-csv", "test.csv",
		"-url", "http://test",
		"-method", "PUT",
		"-concurrency", "32",
		"-rps", "100",
		"-jitter-ms", "10",
		"-delay-ms", "5",
		"-timeout-ms", "1000",
		"-max", "500",
		"-shuffle=false",
		"-headers", "X-Test: true",
		"-basic-auth", "user:pass",
		"-insecure-tls",
		"-ok-status", "201",
		"-json-ok=false",
		"-v",
	}
}

// configRuntimeFlagArgs returns generation, runtime, and display flag arguments.
func configRuntimeFlagArgs() []string {
	return []string{
		"-generate-csv",
		"-generate-count", "50",
		"-generate-cidr-prob", testHalfFlagValue,
		"-generate-cidr-prefix", "28",
		"-csv-delim", "tab",
		"-csv-debug",
		"-loops", "3",
		"-duration", "5m",
		"-max-parallel", "5",
		"-parallel-prob", "0.1",
		"-abort-prob", "0.05",
		"-progress-interval", "10s",
		"-compare-parallel",
		"-idempotency-key",
		"-progress-bar",
		"-color", "always",
	}
}

// configThresholdFlagArgs returns threshold-related flag arguments.
func configThresholdFlagArgs() []string {
	return []string{
		"-warn-p95", "150",
		"-crit-p95", "250",
		"-warn-error-rate", "0.2",
		"-crit-error-rate", "0.8",
		"-warn-track", "0.9",
		"-crit-track", "0.75",
		"-grace-seconds", "5",
	}
}

// configAutoFlagArgs returns adaptive-control flag arguments.
func configAutoFlagArgs() []string {
	return []string{
		"-auto",
		"-auto-target-p95", "350",
		"-auto-max-rps", "500",
		"-auto-max-concurrency", "100",
		"-auto-start-rps", "10",
		"-auto-start-concurrency", "5",
		"-auto-step-rps", "2.5",
		"-auto-step-concurrency", "2",
		"-auto-backoff", testHalfFlagValue,
		"-auto-max-err", "2.0",
		"-auto-min-sample", "100",
		"-auto-focus", "both",
		"-auto-plateau",
		"-auto-plateau-windows", "5",
		"-auto-plateau-gain", "1.5",
		"-auto-plateau-action", "backoff",
		"-auto-plateau-cooldown", "5",
		"-auto-plateau-track-threshold", "0.85",
		"-auto-plateau-track-windows", "4",
		"-auto-plateau-track-action", "shift",
	}
}

// configRandomFlagArgs returns stochastic mutation flag arguments.
func configRandomFlagArgs() []string {
	return []string{
		"-random-no-auth",
		"-random-no-auth-prob", "0.01",
		"-random-bad-pass",
		"-random-bad-pass-prob", "0.02",
		"-debug",
	}
}

// assertConfigFlagValues verifies the parsed flag values as one coherent contract.
func assertConfigFlagValues(t *testing.T, cfg *Config) {
	t.Helper()

	assertRequestConfigFlagValues(t, cfg)
	assertRuntimeConfigFlagValues(t, cfg)
	assertThresholdConfigFlagValues(t, cfg)
	assertAutoConfigFlagValues(t, cfg)
	assertRandomConfigFlagValues(t, cfg)
}

// assertRequestConfigFlagValues verifies request and input flag values.
func assertRequestConfigFlagValues(t *testing.T, cfg *Config) {
	t.Helper()
	assert.Equal(t, "test.csv", cfg.CSVPath)
	assert.Equal(t, "http://test", cfg.Endpoint)
	assert.Equal(t, "PUT", cfg.Method)
	assert.Equal(t, 32, cfg.Concurrency)
	assert.Equal(t, 100.0, cfg.RPS)
	assert.Equal(t, 10, cfg.JitterMs)
	assert.Equal(t, 5, cfg.DelayMs)
	assert.Equal(t, 1000, cfg.TimeoutMs)
	assert.Equal(t, 500, cfg.MaxRows)
	assert.False(t, cfg.Shuffle)
	assert.Equal(t, "X-Test: true", cfg.HeadersList)
	assert.Equal(t, "user:pass", cfg.BasicAuth)
	assert.True(t, cfg.InsecureTLS)
	assert.Equal(t, 201, cfg.OKStatus)
	assert.False(t, cfg.UseJSONFlag)
	assert.True(t, cfg.Verbose)
}

// assertRuntimeConfigFlagValues verifies generation, runtime, and display flag values.
func assertRuntimeConfigFlagValues(t *testing.T, cfg *Config) {
	t.Helper()
	assert.True(t, cfg.GenCSV)
	assert.Equal(t, 50, cfg.GenCount)
	assert.Equal(t, 0.5, cfg.GenCIDRProb)
	assert.Equal(t, 28, cfg.GenCIDRPrefix)
	assert.Equal(t, "tab", cfg.CSVDelim)
	assert.True(t, cfg.CSVDebug)
	assert.Equal(t, 3, cfg.Loops)
	assert.Equal(t, 5*time.Minute, cfg.RunFor)
	assert.Equal(t, 5, cfg.MaxParallel)
	assert.Equal(t, 0.1, cfg.ParallelProb)
	assert.Equal(t, 0.05, cfg.AbortProb)
	assert.Equal(t, 10*time.Second, cfg.ProgressEvery)
	assert.True(t, cfg.CompareParallel)
	assert.True(t, cfg.UseIdemKey)
	assert.True(t, cfg.ProgressBar)
	assert.Equal(t, "always", cfg.ColorMode)
}

// assertThresholdConfigFlagValues verifies warning and critical threshold flag values.
func assertThresholdConfigFlagValues(t *testing.T, cfg *Config) {
	t.Helper()
	assert.Equal(t, 150, cfg.WarnP95)
	assert.Equal(t, 250, cfg.CritP95)
	assert.Equal(t, 0.2, cfg.WarnErr)
	assert.Equal(t, 0.8, cfg.CritErr)
	assert.Equal(t, 0.9, cfg.WarnTrack)
	assert.Equal(t, 0.75, cfg.CritTrack)
	assert.Equal(t, 5, cfg.GraceSeconds)
}

// assertAutoConfigFlagValues verifies adaptive-control flag values.
func assertAutoConfigFlagValues(t *testing.T, cfg *Config) {
	t.Helper()
	assert.True(t, cfg.AutoMode)
	assert.Equal(t, 350, cfg.AutoTargetP95)
	assert.Equal(t, 500.0, cfg.AutoMaxRPS)
	assert.Equal(t, 100, cfg.AutoMaxConc)
	assert.Equal(t, 10.0, cfg.AutoStartRPS)
	assert.Equal(t, 5, cfg.AutoStartConc)
	assert.Equal(t, 2.5, cfg.AutoStepRPS)
	assert.Equal(t, 2, cfg.AutoStepConc)
	assert.Equal(t, 0.5, cfg.AutoBackoff)
	assert.Equal(t, 2.0, cfg.AutoMaxErr)
	assert.Equal(t, 100, cfg.AutoMinSample)
	assert.Equal(t, "both", cfg.AutoFocus)
	assert.True(t, cfg.AutoPlateau)
	assert.Equal(t, 5, cfg.AutoPlateauWindows)
	assert.Equal(t, 1.5, cfg.AutoPlateauGain)
	assert.Equal(t, "backoff", cfg.AutoPlateauAction)
	assert.Equal(t, 5, cfg.AutoPlateauCooldown)
	assert.Equal(t, 0.85, cfg.AutoPlateauTrackThreshold)
	assert.Equal(t, 4, cfg.AutoPlateauTrackWindows)
	assert.Equal(t, "shift", cfg.AutoPlateauTrackAction)
}

// assertRandomConfigFlagValues verifies stochastic mutation flag values.
func assertRandomConfigFlagValues(t *testing.T, cfg *Config) {
	t.Helper()
	assert.True(t, cfg.RandomNoAuth)
	assert.Equal(t, 0.01, cfg.RandomNoAuthProb)
	assert.True(t, cfg.RandomBadPass)
	assert.Equal(t, 0.02, cfg.RandomBadPassProb)
	assert.True(t, cfg.Debug)
}

func TestSeverityLogic(t *testing.T) {
	cfg := severityTestConfig()

	for _, tt := range severityLogicCases() {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, severityForTestStats(cfg, tt.stats))
		})
	}
}

type severityLogicCase struct {
	name     string
	stats    Stats
	expected string
}

// severityTestConfig returns the threshold settings covered by TestSeverityLogic.
func severityTestConfig() *Config {
	cfg := DefaultConfig()
	cfg.WarnP95 = 100
	cfg.CritP95 = 200
	cfg.WarnErr = 1.0
	cfg.CritErr = 5.0
	cfg.WarnTrack = 0.9
	cfg.CritTrack = 0.8

	return cfg
}

// severityLogicCases returns all threshold scenarios covered by TestSeverityLogic.
func severityLogicCases() []severityLogicCase {
	cases := severityLatencyCases()
	cases = append(cases, severityErrorCases()...)
	cases = append(cases, severityTrackingCases()...)

	return cases
}

// severityLatencyCases covers latency-threshold severity transitions.
func severityLatencyCases() []severityLogicCase {
	return []severityLogicCase{
		{
			name: "OK",
			stats: Stats{
				P95:       50 * time.Millisecond,
				HTTPErrs:  0,
				Total:     100,
				TargetRPS: 100,
			},
			expected: severityOK,
		},
		{
			name: "Warn P95",
			stats: Stats{
				P95:       150 * time.Millisecond,
				HTTPErrs:  0,
				Total:     100,
				TargetRPS: 100,
			},
			expected: severityWarn,
		},
		{
			name: "Crit P95",
			stats: Stats{
				P95:       250 * time.Millisecond,
				HTTPErrs:  0,
				Total:     100,
				TargetRPS: 100,
			},
			expected: severityCrit,
		},
	}
}

// severityErrorCases covers error-rate severity transitions.
func severityErrorCases() []severityLogicCase {
	return []severityLogicCase{
		{
			name: "Warn Error",
			stats: Stats{
				P95:       50 * time.Millisecond,
				HTTPErrs:  2,
				Total:     100,
				TargetRPS: 100,
			},
			expected: severityWarn,
		},
		{
			name: "Crit Error",
			stats: Stats{
				P95:       50 * time.Millisecond,
				HTTPErrs:  6,
				Total:     100,
				TargetRPS: 100,
			},
			expected: severityCrit,
		},
	}
}

// severityTrackingCases covers target-RPS tracking severity transitions.
func severityTrackingCases() []severityLogicCase {
	return []severityLogicCase{
		{
			name: "Warn Track",
			stats: Stats{
				P95:       50 * time.Millisecond,
				HTTPErrs:  0,
				Total:     85, // 85 RPS if elapsed is 1s
				Elapsed:   1 * time.Second,
				TargetRPS: 100,
			},
			expected: severityWarn,
		},
		{
			name: "Crit Track",
			stats: Stats{
				P95:       50 * time.Millisecond,
				HTTPErrs:  0,
				Total:     75,
				Elapsed:   1 * time.Second,
				TargetRPS: 100,
			},
			expected: severityCrit,
		},
	}
}

// severityForTestStats mirrors the threshold checks covered by TestSeverityLogic.
func severityForTestStats(cfg *Config, stats Stats) string {
	rps := statsRPSForTest(stats)
	trackingRatio := trackingRatioForTest(stats, rps)
	errRate := CalcErrorRatePct(stats)

	if stats.P95 >= time.Duration(cfg.CritP95)*time.Millisecond || errRate >= cfg.CritErr || (stats.TargetRPS > 0 && trackingRatio <= cfg.CritTrack) {
		return severityCrit
	}

	if stats.P95 >= time.Duration(cfg.WarnP95)*time.Millisecond || errRate >= cfg.WarnErr || (stats.TargetRPS > 0 && trackingRatio <= cfg.WarnTrack) {
		return severityWarn
	}

	return severityOK
}

// statsRPSForTest computes the observed RPS fallback used by the severity test.
func statsRPSForTest(stats Stats) float64 {
	if stats.Elapsed.Seconds() > 0 {
		return float64(stats.Total) / stats.Elapsed.Seconds()
	}

	if stats.Total > 0 {
		return float64(stats.Total)
	}

	return 0
}

// trackingRatioForTest computes target-RPS tracking for the severity test.
func trackingRatioForTest(stats Stats, rps float64) float64 {
	if stats.TargetRPS <= 0 {
		return 1
	}

	return Clamp01(rps / stats.TargetRPS)
}
