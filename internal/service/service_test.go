package service

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

type fakeCrypt struct {
	keys map[string]string
	pol  map[string]string
}

func newCrypt() *fakeCrypt {
	return &fakeCrypt{keys: map[string]string{}, pol: map[string]string{}}
}

func (f *fakeCrypt) AddKey(dir string, raw []byte) (string, error) {
	id := string(raw[:4])
	f.keys[dir] = id
	return id, nil
}

func (f *fakeCrypt) RemoveKey(dir, id string) error {
	if f.keys[dir] != id {
		return errors.New("not added")
	}
	delete(f.keys, dir)
	return nil
}

func (f *fakeCrypt) SetPolicy(dir, id string) error {
	f.pol[dir] = id
	return nil
}

func setup(t *testing.T, name string) (*Service, *fakeCrypt, string, string) {
	t.Helper()
	media := t.TempDir()
	drive := filepath.Join(media, "KEY")
	os.MkdirAll(drive, 0o755)
	c := newCrypt()
	s := New(Config{TPM: tpm.NewFake(name), Crypt: c, Mounts: []string{media + "/"}, SysRoot: t.TempDir()})
	return s, c, media, drive
}

func errName(err *dbus.Error) string {
	if err == nil {
		return ""
	}
	return strings.TrimPrefix(err.Name, errorPfx)
}

func TestLifecycle(t *testing.T) {
	s, c, media, drive := setup(t, "pc-a")
	if _, err := s.Create(media, "482915"); errName(err) != "NotAllowed" {
		t.Fatalf("the media directory itself: %v", err)
	}
	if _, err := s.Create("/etc", "482915"); errName(err) != "NotAllowed" {
		t.Fatalf("a system directory: %v", err)
	}
	link := filepath.Join(media, "escape")
	os.Symlink("/etc", link)
	if _, err := s.Create(link, "482915"); errName(err) != "NotAllowed" {
		t.Fatalf("a symlink out of the media directory: %v", err)
	}
	if _, _, _, _, err := s.Inspect(drive); errName(err) != "NotAKey" {
		t.Fatalf("empty drive: %v", err)
	}
	code, err := s.Create(drive, "482915")
	if err != nil || len(code) != 29 {
		t.Fatalf("create: %q %v", code, err)
	}
	data := filepath.Join(drive, DataDir)
	if c.keys[data] == "" || c.pol[data] != c.keys[data] {
		t.Fatal("new Key data is not encrypted with its key")
	}
	if _, err := s.Create(drive, "482915"); errName(err) != "Exists" {
		t.Fatalf("created twice: %v", err)
	}
	if err := s.Lock(drive); err != nil || c.keys[data] != "" {
		t.Fatalf("lock: %v", err)
	}
	if _, err := s.Unlock(drive, "111111"); errName(err) != "WrongPin" {
		t.Fatalf("wrong PIN: %v", err)
	}
	if mode, err := s.Unlock(drive, "482915"); err != nil || mode != "guest" {
		t.Fatalf("guest: %s %v", mode, err)
	}
	if err := s.Remember(drive, "482915", ""); err != nil {
		t.Fatal(err)
	}
	id, level, mode, slots, derr := s.Inspect(drive)
	if derr != nil || id == "" || level != "base" || mode != "guest" || len(slots) != 1 {
		t.Fatalf("inspect: %s %s %s %v %v", id, level, mode, slots, derr)
	}
	if slots[0].Name != "Computer" || slots[0].Firmware != "generic" || !slots[0].Here {
		t.Fatalf("slot: %v", slots[0])
	}
	s.Lock(drive)
	if mode, err := s.Unlock(drive, "482915"); err != nil || mode != "trusted" {
		t.Fatalf("trusted: %s %v", mode, err)
	}
	if err := s.ChangePin(drive, "482915", "12"); errName(err) != "ShortPin" {
		t.Fatalf("short PIN: %v", err)
	}
	if err := s.Recover(drive, "00000-00000-00000-00000-00000", "735190"); errName(err) != "WrongCode" {
		t.Fatalf("wrong code: %v", err)
	}
	if err := s.Recover(drive, code, "735190"); err != nil {
		t.Fatal(err)
	}
	s.Lock(drive)
	if mode, err := s.Unlock(drive, "735190"); err != nil || mode != "trusted" {
		t.Fatalf("after recovery: %s %v", mode, err)
	}
	pc := slots[0].PC
	if err := s.Forget(drive, "735190", pc); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget(drive, "735190", pc); errName(err) != "NotRemembered" {
		t.Fatalf("forget twice: %v", err)
	}
}

func TestOverTheBus(t *testing.T) {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	addr, _ := bufio.NewReader(out).ReadString('\n')
	server, err := dbus.Connect(strings.TrimSpace(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	s, _, _, drive := setup(t, "pc-a")
	if err := Export(server, s); err != nil {
		t.Fatal(err)
	}
	if r, err := server.RequestName(Name, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("name")
	}
	client, err := dbus.Connect(strings.TrimSpace(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	obj := client.Object(Name, Path)
	var code string
	if err := obj.Call(Iface+".Create", 0, drive, "482915").Store(&code); err != nil || len(code) != 29 {
		t.Fatalf("create: %v", err)
	}
	var unlockedList []string
	if err := obj.StoreProperty(Iface+".Unlocked", &unlockedList); err != nil || len(unlockedList) != 1 {
		t.Fatalf("unlocked property: %v %v", unlockedList, err)
	}
	if err := obj.Call(Iface+".Lock", 0, drive).Err; err != nil {
		t.Fatal(err)
	}
	err = obj.Call(Iface+".Unlock", 0, drive, "000000").Err
	var de dbus.Error
	if !errors.As(err, &de) || de.Name != errorPfx+"WrongPin" {
		t.Fatalf("wrong PIN over the bus: %v", err)
	}
	var mode string
	if err := obj.Call(Iface+".Unlock", 0, drive, "482915").Store(&mode); err != nil || mode != "guest" {
		t.Fatalf("unlock: %s %v", mode, err)
	}
	var id, level string
	var slots []SlotInfo
	call := obj.Call(Iface+".Inspect", 0, drive)
	if err := call.Store(&id, &level, &mode, &slots); err != nil || level != "base" || mode != "guest" {
		t.Fatalf("inspect: %v", err)
	}
	if len(slots) != 0 {
		t.Fatalf("slots before remembering: %v", slots)
	}
	var xml string
	if err := obj.Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&xml); err != nil || !strings.Contains(xml, `type="a(sssxb)"`) {
		t.Fatalf("slots are not a(sssxb): %v", err)
	}
}
