package util

import (
	"testing"
)

func TestComparePasswords(t *testing.T) {
	var testCases = []struct {
		Name            string
		HashedPassword  string
		PlainPassword   string
		ExpectedOutcome bool
		ExpectingError  bool
	}{
		{
			"matching password ARGON2",
			"$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo",
			"abc123",
			true,
			false,
		},
		{
			"non-matching password ARGON2",
			"$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo",
			"abc124",
			false,
			false,
		},
		{
			"invalid format",
			"{QWE}123",
			"abc123",
			false,
			true,
		},
		{
			"matching password SSHA256",
			"{SSHA256}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==",
			"bc123",
			true,
			false,
		},
		{
			"non-matching password SSHA256.B64",
			"{SSHA256.B64}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==",
			"bc120",
			false,
			false,
		},
		{
			"invalid format suffix defaults to B64",
			"{SSHA256.BIN}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==",
			"bc123",
			true,
			false,
		},
		{
			"empty hashed password",
			"",
			"abc123",
			false,
			true,
		},
		{
			"empty plain password",
			"$argon2id$v=19$m=65536,t=2,p=1$gCxez+B/Sr5ogq0o+y+7Ig$hKxxLmCF5pMVjcBk+seY7DeLx6RBfNoD/LUg1VZjAuo",
			"",
			false,
			false,
		},
		{
			"empty both password",
			"",
			"",
			false,
			true,
		},
	}

	for _, testCase := range testCases {
		outcome, err := ComparePasswords(testCase.HashedPassword, testCase.PlainPassword)

		if testCase.ExpectingError {
			if err == nil {
				t.Errorf("Expected error but got none for the test case: %s", testCase.Name)
			}
		} else {
			if err != nil {
				t.Errorf("Did not expect error but got one for the test case: %s. Error: %s", testCase.Name, err.Error())
			}

			if outcome != testCase.ExpectedOutcome {
				t.Errorf("Expected outcome '%v' but got '%v' for the test case: %s", testCase.ExpectedOutcome, outcome, testCase.Name)
			}
		}
	}
}
