package key

import (
	"errors"
	"os"
	"testing"

	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

func TestWithRealTPM(t *testing.T) {
	path := os.Getenv("SINTYKEY_TPM_HELPER")
	if path == "" {
		t.Skip("SINTYKEY_TPM_HELPER not set")
	}
	h := &tpm.Helper{Path: path, WorkDir: t.TempDir()}
	k, code := newKey(t)
	if err := k.Remember(h, "482915", "Desk", "generic"); err != nil {
		t.Fatal(err)
	}
	clone := copyKey(t, k.Root)
	if _, mode, err := reopen(t, k.Root).Unlock(h, "482915"); err != nil || mode != Trusted {
		t.Fatalf("trusted unlock: %v %s", err, mode)
	}
	if _, _, err := reopen(t, k.Root).Unlock(h, "000000"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("wrong PIN: %v", err)
	}
	if _, _, err := reopen(t, clone).Unlock(h, "482915"); !errors.Is(err, ErrCopy) {
		t.Fatalf("older copy: %v", err)
	}
	if err := reopen(t, k.Root).Recover(h, code, "735190"); err != nil {
		t.Fatal(err)
	}
	if _, mode, err := reopen(t, k.Root).Unlock(h, "735190"); err != nil || mode != Trusted {
		t.Fatalf("after recovery: %v %s", err, mode)
	}
}
