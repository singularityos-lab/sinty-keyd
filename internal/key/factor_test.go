package key

import (
	"bytes"
	"errors"
	"testing"

	"github.com/singularityos-lab/sinty-keyd/internal/fido2"
	"github.com/singularityos-lab/sinty-keyd/internal/keyfile"
	"github.com/singularityos-lab/sinty-keyd/internal/seal"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

func securityKey() *fido2.Client {
	return &fido2.Client{T: fido2.NewSoft()}
}

func with(t *testing.T, root string, f SecondFactor) *Key {
	t.Helper()
	k := reopen(t, root)
	k.Second = f
	return k
}

func TestStrongKey(t *testing.T) {
	k, code := newKey(t)
	pc := tpm.NewFake("pc-a")
	if err := k.Remember(pc, "482915", "Desk", ""); err != nil {
		t.Fatal(err)
	}
	a, b, c := securityKey(), securityKey(), securityKey()
	if _, err := reopen(t, k.Root).AddFactor(pc, "000000", a, "Blue", ""); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("added with wrong PIN: %v", err)
	}
	idA, err := reopen(t, k.Root).AddFactor(pc, "482915", a, "Blue", "")
	if err != nil {
		t.Fatal(err)
	}
	h := reopen(t, k.Root).Header
	if h.Format != keyfile.Format || len(h.Factors) != 1 || h.Factors[0].Name != "Blue" {
		t.Fatalf("header after add: %+v", h)
	}
	if _, err := seal.Unwrap(h.Guest, guestSecret("482915", h.Secret, nil)); err == nil {
		t.Fatal("the PIN alone still opens a strong Key")
	}
	if _, _, err := reopen(t, k.Root).Unlock(pc, "482915"); !errors.Is(err, ErrFactorRequired) {
		t.Fatalf("unlock without the security key: %v", err)
	}
	if _, _, err := with(t, k.Root, c).Unlock(pc, "482915"); !errors.Is(err, ErrUnknownFactor) {
		t.Fatalf("unlock with a stranger's key: %v", err)
	}
	if _, _, err := with(t, k.Root, a).Unlock(pc, "000000"); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("wrong PIN with the security key: %v", err)
	}
	master, mode, err := with(t, k.Root, a).Unlock(pc, "482915")
	if err != nil || mode != Trusted {
		t.Fatalf("trusted strong unlock: %v %s", err, mode)
	}
	s := reopen(t, k.Root).Header.Slot(mustFingerprint(t, pc))
	if sealed, err := pc.Unseal("482915", s.Public, s.Private); err != nil || bytes.Equal(sealed, master) {
		t.Fatalf("the TPM alone yields the master key: %v", err)
	}
	if _, mode, err := with(t, k.Root, a).Unlock(tpm.NewFake("pc-b"), "482915"); err != nil || mode != Guest {
		t.Fatalf("guest strong unlock: %v %s", err, mode)
	}

	if _, err := with(t, k.Root, a).AddFactor(pc, "482915", a, "Again", ""); !errors.Is(err, ErrFactorExists) {
		t.Fatalf("same security key twice: %v", err)
	}
	idB, err := with(t, k.Root, a).AddFactor(pc, "482915", b, "Spare", "")
	if err != nil {
		t.Fatal(err)
	}
	m2, _, err := with(t, k.Root, b).Unlock(pc, "482915")
	if err != nil || !bytes.Equal(m2, master) {
		t.Fatalf("spare key unlock: %v", err)
	}

	if err := reopen(t, k.Root).Recover(pc, code, "735190"); err != nil {
		t.Fatalf("recovery without a security key: %v", err)
	}
	if _, _, err := reopen(t, k.Root).Unlock(pc, "735190"); !errors.Is(err, ErrFactorRequired) {
		t.Fatalf("recovery dropped the security key: %v", err)
	}
	if _, mode, err := with(t, k.Root, b).Unlock(pc, "735190"); err != nil || mode != Trusted {
		t.Fatalf("after recovery: %v %s", err, mode)
	}

	if err := with(t, k.Root, b).RemoveFactor(pc, "735190", idA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := with(t, k.Root, a).Unlock(pc, "735190"); !errors.Is(err, ErrUnknownFactor) {
		t.Fatalf("removed key still opens: %v", err)
	}
	if err := with(t, k.Root, b).RemoveFactor(pc, "735190", idA); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("removed twice: %v", err)
	}
	if err := with(t, k.Root, b).RemoveFactor(pc, "735190", idB); err != nil {
		t.Fatal(err)
	}
	h = reopen(t, k.Root).Header
	if h.Format != keyfile.FormatBase || h.Strong() || h.FactorKey != nil {
		t.Fatalf("header after the last removal: %+v", h)
	}
	m3, mode, err := reopen(t, k.Root).Unlock(pc, "735190")
	if err != nil || mode != Trusted || !bytes.Equal(m3, master) {
		t.Fatalf("plain unlock after removal: %v %s", err, mode)
	}
}

func TestRecoverWithoutFactors(t *testing.T) {
	k, code := newKey(t)
	a := securityKey()
	if _, err := reopen(t, k.Root).AddFactor(nil, "482915", a, "Blue", ""); err != nil {
		t.Fatal(err)
	}
	if err := reopen(t, k.Root).RecoverWithoutFactors(nil, "wrong", "735190"); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := reopen(t, k.Root).RecoverWithoutFactors(nil, code, "735190"); err != nil {
		t.Fatal(err)
	}
	if _, mode, err := reopen(t, k.Root).Unlock(nil, "735190"); err != nil || mode != Guest {
		t.Fatalf("unlock after the security keys were dropped: %v %s", err, mode)
	}
}

func TestStrongDropsOtherComputers(t *testing.T) {
	k, _ := newKey(t)
	here, there := tpm.NewFake("pc-a"), tpm.NewFake("pc-b")
	for _, pc := range []*tpm.Fake{here, there} {
		if err := reopen(t, k.Root).Remember(pc, "482915", "PC", ""); err != nil {
			t.Fatal(err)
		}
	}
	a := securityKey()
	if _, err := reopen(t, k.Root).AddFactor(here, "482915", a, "Blue", ""); err != nil {
		t.Fatal(err)
	}
	s := reopen(t, k.Root).Header.Slot(mustFingerprint(t, there))
	if s.Public != nil || s.Private != nil {
		t.Fatal("another computer keeps a TPM seal that skips the security key")
	}
	if _, mode, err := with(t, k.Root, a).Unlock(there, "482915"); err != nil || mode != Trusted {
		t.Fatalf("other computer after strong: %v %s", err, mode)
	}
}

func mustFingerprint(t *testing.T, pc tpm.TPM) string {
	t.Helper()
	fp, err := pc.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return fp
}
