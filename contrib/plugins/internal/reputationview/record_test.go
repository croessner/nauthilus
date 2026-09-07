package reputationview

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"testing"
)

// TestTupleRecordConditionalContract requires identical validation at producer and composition boundaries.
func TestTupleRecordConditionalContract(t *testing.T) {
	cases := []Tuple{
		{State: NotFound, Profile: "operational", Band: Unknown, Override: NoOverride},
		{State: Unavailable, Profile: "fast", Band: Unavailable, Override: NoOverride},
		{State: NotFound, Profile: "baseline", Band: Blocked, Override: Blocked},
		{State: Fresh, Profile: "operational", Band: Positive, Override: NoOverride, Details: &Details{Trust: .7, Samples: 30, Confidence: .8, Diversity: 2, AgeSeconds: 20}},
		{State: Stale, Profile: "operational", Band: Suspicious, Override: NoOverride, Details: &Details{Risk: .7, Samples: 30, Confidence: .8, Diversity: 2, AgeSeconds: 20}},
	}
	for _, tuple := range cases {
		fields, err := Encode(tuple)
		if err != nil {
			t.Fatal(err)
		}

		got, err := Decode(fields)
		if err != nil || got.State != tuple.State || got.Band != tuple.Band {
			t.Fatalf("round trip: %#v %v", got, err)
		}

		fields["unknown"] = pluginapi.DecisionRecordFieldValue{}
		if _, err := Decode(fields); err == nil {
			t.Fatal("unknown tuple field accepted")
		}

		delete(fields, "unknown")

		if tuple.Details != nil {
			delete(fields, "risk_score")

			if _, err := Decode(fields); err == nil {
				t.Fatal("partial measured tuple accepted")
			}
		}
	}
}
