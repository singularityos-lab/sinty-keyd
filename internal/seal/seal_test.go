package seal

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWrapRoundTrip(t *testing.T) {
	key, _ := Random(KeySize)
	blob, err := Wrap(key, []byte("482915"))
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != BlobSize {
		t.Fatalf("blob is %d bytes, want %d", len(blob), BlobSize)
	}
	back, err := Unwrap(blob, []byte("482915"))
	if err != nil || !bytes.Equal(back, key) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := Unwrap(blob, []byte("482916")); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("wrong secret accepted: %v", err)
	}
	blob[len(blob)-1] ^= 1
	if _, err := Unwrap(blob, []byte("482915")); err == nil {
		t.Fatal("tampered blob accepted")
	}
}

func TestRecoveryCode(t *testing.T) {
	code, err := RecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	groups := strings.Split(code, "-")
	if len(groups) != 5 || len(code) != 29 {
		t.Fatalf("unexpected shape %q", code)
	}
	if NormalizeCode(strings.ToLower(strings.ReplaceAll(code, "-", " "))) != code {
		t.Fatalf("normalize does not restore %q", code)
	}
	if NormalizeCode("abcde-oil11") != "ABCDE-01111" {
		t.Fatalf("ambiguous glyphs: %q", NormalizeCode("abcde-oil11"))
	}
}
