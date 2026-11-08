package key

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singularityos-lab/sinty-keyd/internal/keyfile"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

func newKey(t *testing.T) (*Key, string) {
	t.Helper()
	root := t.TempDir()
	k, code, err := Create(root, "482915")
	if err != nil {
		t.Fatal(err)
	}
	return k, code
}

func reopen(t *testing.T, root string) *Key {
	t.Helper()
	k, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func copyKey(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	data, err := os.ReadFile(keyfile.Path(from))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(to, keyfile.Dir), 0o700)
	if err := os.WriteFile(keyfile.Path(to), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return to
}

func TestGuestUnlock(t *testing.T) {
	k, _ := newKey(t)
	if _, _, err := Create(k.Root, "123456"); !errors.Is(err, ErrExists) {
		t.Fatalf("created twice: %v", err)
	}
	k = reopen(t, k.Root)
	master, mode, err := k.Unlock(nil, "482915")
	if err != nil || mode != Guest || len(master) != 32 {
		t.Fatalf("guest unlock: %v %s", err, mode)
	}
	if _, _, err := k.Unlock(tpm.NewFake("pc-a"), "000000"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("wrong PIN: %v", err)
	}
	if _, _, err := Create(t.TempDir(), "12"); !errors.Is(err, ErrShortPIN) {
		t.Fatalf("short PIN accepted: %v", err)
	}
}

func TestRememberedComputer(t *testing.T) {
	k, _ := newKey(t)
	a := tpm.NewFake("pc-a")
	if err := k.Remember(a, "482915", "Desk", "amd"); err != nil {
		t.Fatal(err)
	}
	k = reopen(t, k.Root)
	guest, _, _ := k.Unlock(nil, "482915")
	master, mode, err := k.Unlock(a, "482915")
	if err != nil || mode != Trusted {
		t.Fatalf("trusted unlock: %v %s", err, mode)
	}
	if !bytes.Equal(master, guest) {
		t.Fatal("trusted and guest unlock disagree on the key")
	}
	if _, _, err := k.Unlock(a, "111111"); !errors.Is(err, ErrWrongPIN) || a.Failures != 1 {
		t.Fatalf("wrong PIN on a remembered computer: %v, %d TPM failures", err, a.Failures)
	}
	pc, _ := a.Fingerprint()
	s := reopen(t, k.Root).Header.Slot(pc)
	if s == nil || s.Name != "Desk" || s.Firmware != "amd" || s.Generation != 2 {
		t.Fatalf("slot after two unlocks: %+v", s)
	}
	_, mode, err = reopen(t, k.Root).Unlock(tpm.NewFake("pc-b"), "482915")
	if err != nil || mode != Guest {
		t.Fatalf("other computer: %v %s", err, mode)
	}
}

func TestCopyIsRefused(t *testing.T) {
	k, code := newKey(t)
	a := tpm.NewFake("pc-a")
	if err := k.Remember(a, "482915", "Desk", ""); err != nil {
		t.Fatal(err)
	}
	clone := copyKey(t, k.Root)
	if _, _, err := reopen(t, k.Root).Unlock(a, "482915"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopen(t, clone).Unlock(a, "482915"); !errors.Is(err, ErrCopy) {
		t.Fatalf("older copy unlocked: %v", err)
	}
	if _, mode, err := reopen(t, clone).Unlock(tpm.NewFake("pc-b"), "482915"); err != nil || mode != Guest {
		t.Fatalf("copy as guest elsewhere: %v %s", err, mode)
	}
	if _, mode, err := reopen(t, k.Root).Unlock(a, "482915"); err != nil || mode != Trusted {
		t.Fatalf("the real Key after the copy was refused: %v %s", err, mode)
	}
	lost := reopen(t, k.Root)
	backup := copyKey(t, k.Root)
	if err := reopen(t, backup).Recover(a, code, "975310"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lost.Unlock(a, "482915"); !errors.Is(err, ErrCopy) {
		t.Fatalf("lost Key still unlocks after recovery: %v", err)
	}
}

func TestChangePIN(t *testing.T) {
	k, _ := newKey(t)
	a, b := tpm.NewFake("pc-a"), tpm.NewFake("pc-b")
	if err := k.Remember(a, "482915", "Desk", ""); err != nil {
		t.Fatal(err)
	}
	if err := k.Remember(b, "482915", "Laptop", ""); err != nil {
		t.Fatal(err)
	}
	if err := reopen(t, k.Root).ChangePIN(a, "000000", "735190"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("changed with a wrong PIN: %v", err)
	}
	if err := reopen(t, k.Root).ChangePIN(a, "482915", "735190"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopen(t, k.Root).Unlock(a, "482915"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("old PIN still works: %v", err)
	}
	if _, mode, err := reopen(t, k.Root).Unlock(a, "735190"); err != nil || mode != Trusted {
		t.Fatalf("new PIN here: %v %s", err, mode)
	}
	if _, _, err := reopen(t, k.Root).Unlock(b, "482915"); err == nil {
		t.Fatal("old PIN works on the other computer")
	}
	if _, mode, err := reopen(t, k.Root).Unlock(b, "735190"); err != nil || mode != Trusted {
		t.Fatalf("new PIN on the other computer: %v %s", err, mode)
	}
	pc, _ := b.Fingerprint()
	if s := reopen(t, k.Root).Header.Slot(pc); s.PINEpoch != reopen(t, k.Root).Header.PINEpoch {
		t.Fatal("other computer was not sealed again")
	}
}

func TestRecover(t *testing.T) {
	k, code := newKey(t)
	if err := reopen(t, k.Root).Recover(nil, "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA", "246810"); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("wrong code: %v", err)
	}
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if err := reopen(t, k.Root).Recover(nil, typed, "246810"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopen(t, k.Root).Unlock(nil, "246810"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopen(t, k.Root).Unlock(nil, "482915"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("forgotten PIN still works: %v", err)
	}
}

func TestTamperedHeader(t *testing.T) {
	k, _ := newKey(t)
	a := tpm.NewFake("pc-a")
	if err := k.Remember(a, "482915", "Desk", ""); err != nil {
		t.Fatal(err)
	}
	h := reopen(t, k.Root).Header
	h.Slots[0].Generation = 99
	if err := keyfile.Write(k.Root, h); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopen(t, k.Root).Unlock(a, "482915"); !errors.Is(err, keyfile.ErrTampered) {
		t.Fatalf("tampered header accepted: %v", err)
	}
}

func TestForget(t *testing.T) {
	k, _ := newKey(t)
	a := tpm.NewFake("pc-a")
	if err := k.Remember(a, "482915", "Desk", ""); err != nil {
		t.Fatal(err)
	}
	clone := copyKey(t, k.Root)
	pc, _ := a.Fingerprint()
	if err := reopen(t, k.Root).Forget(a, "482915", pc); err != nil {
		t.Fatal(err)
	}
	if _, mode, err := reopen(t, k.Root).Unlock(a, "482915"); err != nil || mode != Guest {
		t.Fatalf("forgotten computer: %v %s", err, mode)
	}
	if _, _, err := reopen(t, clone).Unlock(a, "482915"); !errors.Is(err, ErrCopy) {
		t.Fatalf("copy made before forgetting still trusted: %v", err)
	}
	if err := reopen(t, k.Root).Forget(a, "482915", pc); !errors.Is(err, ErrNotRemembered) {
		t.Fatalf("forgot twice: %v", err)
	}
}

func TestDataKey(t *testing.T) {
	m := bytes.Repeat([]byte{7}, 32)
	a, b := DataKey(m), DataKey(m)
	if len(a) != 64 || !bytes.Equal(a, b) || bytes.Equal(a[:32], m) {
		t.Fatal("data key")
	}
}
