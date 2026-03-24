package util

import "testing"

func TestURLPartialDecode(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "NoEncoding",
			input: "plain-value",
			want:  "plain-value",
		},
		{
			name:  "DecodePercentAndSpace",
			input: "my%20pass%25word",
			want:  "my pass%word",
		},
		{
			name:  "PlusSignRemainsPlus",
			input: "pass+word%2Bnext",
			want:  "pass+word+next",
		},
		{
			name:  "LowercaseHex",
			input: "alpha%2fbeta",
			want:  "alpha/beta",
		},
		{
			name:  "MixedValidAndInvalidEscapes",
			input: "a%20b%2Gc%ZZd",
			want:  "a b%2Gc%ZZd",
		},
		{
			name:  "TrailingPercentRemains",
			input: "abc%",
			want:  "abc%",
		},
		{
			name:  "DoubleEncodedPercentDecodedOnce",
			input: "100%2525",
			want:  "100%25",
		},
		{
			name:  "UTF8Sequence",
			input: "J%C3%B6rg",
			want:  "Jörg",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := URLPartialDecode(tt.input)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
