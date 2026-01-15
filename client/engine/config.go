package engine

import (
	"time"
)

// Config holds all parameters for the test client.
type Config struct {
	CSVPath         string
	Endpoint        string
	Method          string
	Concurrency     int
	RPS             float64
	JitterMs        int
	DelayMs         int
	TimeoutMs       int
	MaxRows         int
	Shuffle         bool
	HeadersList     string
	BasicAuth       string
	OKStatus        int
	UseJSONFlag     bool
	Verbose         bool
	GenCSV          bool
	GenCount        int
	GenCIDRProb     float64
	GenCIDRPrefix   int
	CSVDelim        string
	CSVDebug        bool
	Loops           int
	RunFor          time.Duration
	MaxParallel     int
	ParallelProb    float64
	AbortProb       float64
	ProgressEvery   time.Duration
	CompareParallel bool
	UseIdemKey      bool
	ProgressBar     bool
	ColorMode       string

	// Thresholds for coloring
	WarnP95   int
	CritP95   int
	WarnErr   float64
	CritErr   float64
	WarnTrack float64
	CritTrack float64

	GraceSeconds int

	// Auto-mode flags
	AutoMode                  bool
	AutoTargetP95             int
	AutoMaxRPS                float64
	AutoMaxConc               int
	AutoStartRPS              float64
	AutoStartConc             int
	AutoStepRPS               float64
	AutoStepConc              int
	AutoBackoff               float64
	AutoMaxErr                float64
	AutoMinSample             int
	AutoFocus                 string
	AutoPlateau               bool
	AutoPlateauWindows        int
	AutoPlateauGain           float64
	AutoPlateauAction         string
	AutoPlateauCooldown       int
	AutoPlateauTrackThreshold float64
	AutoPlateauTrackWindows   int
	AutoPlateauTrackAction    string

	RandomNoAuth      bool
	RandomNoAuthProb  float64
	RandomBadPass     bool
	RandomBadPassProb float64

	Debug bool
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		CSVPath:                   "client/logins.csv",
		Endpoint:                  "http://localhost:8080/api/v1/auth/json",
		Method:                    "POST",
		Concurrency:               16,
		RPS:                       0,
		JitterMs:                  0,
		DelayMs:                   0,
		TimeoutMs:                 5000,
		MaxRows:                   0,
		Shuffle:                   true,
		HeadersList:               "Content-Type: application/json",
		OKStatus:                  200,
		UseJSONFlag:               true,
		Verbose:                   false,
		GenCount:                  10000,
		GenCIDRProb:               0.0,
		GenCIDRPrefix:             24,
		Loops:                     1,
		MaxParallel:               1,
		ProgressEvery:             time.Minute,
		ColorMode:                 "auto",
		WarnP95:                   300,
		CritP95:                   600,
		WarnErr:                   0.5,
		CritErr:                   1.0,
		WarnTrack:                 0.85,
		CritTrack:                 0.70,
		GraceSeconds:              10,
		AutoTargetP95:             400,
		AutoBackoff:               0.7,
		AutoMaxErr:                1.0,
		AutoMinSample:             200,
		AutoFocus:                 "rps",
		AutoPlateauWindows:        3,
		AutoPlateauGain:           5.0,
		AutoPlateauAction:         "freeze",
		AutoPlateauCooldown:       2,
		AutoPlateauTrackThreshold: 0.9,
		AutoPlateauTrackWindows:   0,
		AutoPlateauTrackAction:    "freeze",
	}
}
