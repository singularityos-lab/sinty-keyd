package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/sinty-keyd/internal/fido2"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

type plugged struct{ keys []*fido2.Soft }

func (p *plugged) open() ([]fido2.Transport, error) {
	out := make([]fido2.Transport, len(p.keys))
	for i, k := range p.keys {
		out[i] = k
	}
	return out, nil
}

func TestSecurityKeys(t *testing.T) {
	media := t.TempDir()
	drive := filepath.Join(media, "KEY")
	os.MkdirAll(drive, 0o755)
	blue, spare := fido2.NewSoft(), fido2.NewSoft()
	usb := &plugged{}
	s := New(Config{TPM: tpm.NewFake("pc-a"), Crypt: newCrypt(), Mounts: []string{media + "/"}, SysRoot: t.TempDir(), SecurityKeys: usb.open})
	code, err := s.Create(drive, "482915")
	if err != nil {
		t.Fatal(err)
	}
	s.Lock(drive)
	if _, err := s.AddSecurityKey(drive, "482915", "Blue", ""); errName(err) != "SecurityKeyRequired" {
		t.Fatalf("no security key plugged in: %v", err)
	}
	usb.keys = []*fido2.Soft{blue}
	blue.Deny = true
	if _, err := s.AddSecurityKey(drive, "482915", "Blue", ""); errName(err) != "NotTouched" {
		t.Fatalf("not touched: %v", err)
	}
	blue.Deny = false
	blue.PIN = "1234"
	if _, err := s.AddSecurityKey(drive, "482915", "Blue", ""); errName(err) != "SecurityKeyPinRequired" {
		t.Fatalf("security key PIN missing: %v", err)
	}
	idBlue, err := s.AddSecurityKey(drive, "482915", "Blue", "1234")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSecurityKey(drive, "482915", "Blue again", "1234"); errName(err) != "SecurityKeyExists" {
		t.Fatalf("same key twice: %v", err)
	}
	usb.keys = []*fido2.Soft{blue, spare}
	if _, err := s.AddSecurityKey(drive, "482915", "Spare", ""); err != nil {
		t.Fatal(err)
	}
	list, err := s.SecurityKeys(drive)
	if err != nil || len(list) != 2 || list[0].Name != "Blue" || list[1].Name != "Spare" || list[0].ID != idBlue {
		t.Fatalf("list: %+v %v", list, err)
	}
	usb.keys = nil
	if _, err := s.Unlock(drive, "482915"); errName(err) != "SecurityKeyRequired" {
		t.Fatalf("unlock with no security key: %v", err)
	}
	usb.keys = []*fido2.Soft{fido2.NewSoft()}
	if _, err := s.Unlock(drive, "482915"); errName(err) != "UnknownSecurityKey" {
		t.Fatalf("unlock with a stranger's key: %v", err)
	}
	usb.keys = []*fido2.Soft{spare}
	if mode, err := s.Unlock(drive, "482915"); err != nil || mode != "trusted" && mode != "guest" {
		t.Fatalf("unlock with the spare: %s %v", mode, err)
	}
	s.Lock(drive)
	if err := s.RemoveSecurityKey(drive, "482915", idBlue); err != nil {
		t.Fatal(err)
	}
	usb.keys = []*fido2.Soft{blue}
	if _, err := s.Unlock(drive, "482915"); errName(err) != "UnknownSecurityKey" {
		t.Fatalf("removed key still opens: %v", err)
	}
	usb.keys = nil
	if err := s.RecoverWithoutSecurityKeys(drive, code, "735190"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(drive, "735190"); err != nil {
		t.Fatalf("unlock after recovery without security keys: %v", err)
	}
	if list, _ := s.SecurityKeys(drive); len(list) != 0 {
		t.Fatalf("security keys left: %+v", list)
	}
}
