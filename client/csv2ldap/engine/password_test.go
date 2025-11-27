package engine

import "testing"

func TestSHAEncoder_Base64(t *testing.T) {
	enc := &SHAEncoder{Encoding: "b64"}
	out, err := enc.Encode("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ="
	if out != want {
		t.Fatalf("mismatch:\n got: %s\nwant: %s", out, want)
	}
}

func TestSHAEncoder_Hex(t *testing.T) {
	enc := &SHAEncoder{Encoding: "hex"}
	out, err := enc.Encode("secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{SHA.HEX}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4"
	if out != want {
		t.Fatalf("mismatch:\n got: %s\nwant: %s", out, want)
	}
}
