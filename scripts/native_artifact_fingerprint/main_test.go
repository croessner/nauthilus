package main

import "testing"

// TestCompilerInputsIncludeVendoredSources preserves dependency-code coverage independently of lockfiles.
func TestCompilerInputsIncludeVendoredSources(t *testing.T) {
	for _, test := range []struct {
		path string
		want bool
	}{
		{"vendor/example.test/library/library.go", true},
		{"vendor/example.test/library/bridge.c", true},
		{"vendor/example.test/library/bridge.h", true},
		{"pluginapi/v1/opaque_identifier.go", true},
		{"vendor/modules.txt", true},
		{"runtime/credentials.secret", false},
		{"temp/config.yml", false},
	} {
		t.Run(test.path, func(t *testing.T) {
			if got := compilerInput(test.path); got != test.want {
				t.Fatalf("compiler input=%t, want %t", got, test.want)
			}
		})
	}
}

// TestFingerprintBindsNativeCompiler prevents distinct C toolchains from sharing an artifact identity.
func TestFingerprintBindsNativeCompiler(t *testing.T) {
	t.Setenv("CC", "/usr/bin/cc")

	first, err := fingerprint("")
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("CC", "/bin/false")

	second, err := fingerprint("")
	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Fatal("native compiler change did not change the artifact identity")
	}
}
