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

func TestPruneLocksRemovedDrive(t *testing.T) {
	s, c, media, drive := setup(t, "pc-a")
	info := filepath.Join(t.TempDir(), "mountinfo")
	s.cfg.MountInfo = info
	line := func(p string) string { return "36 25 8:1 / " + p + " rw - vfat /dev/sdb1 rw\n" }
	os.WriteFile(info, []byte(line("/")+line(drive)), 0o644)
	if _, err := s.Create(drive, "482915"); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(drive, DataDir)
	s.Prune()
	if _, ok := s.open[drive]; !ok || c.keys[data] == "" {
		t.Fatal("a mounted Key was locked")
	}
	os.WriteFile(info, []byte(line("/")+line(media+"/OTHER")), 0o644)
	s.Prune()
	if _, ok := s.open[drive]; ok || c.keys[data] != "" {
		t.Fatal("a removed Key stayed unlocked")
	}
}

func TestStillMountedNeedsARemovableMount(t *testing.T) {
	roots := []string{"/run/media/"}
	points := map[string]bool{"/": true, "/run/media/alex/KEY": true}
	if !stillMounted("/run/media/alex/KEY", points, roots) {
		t.Error("mounted Key")
	}
	if stillMounted("/run/media/alex/GONE", points, roots) {
		t.Error("a path left only on the root filesystem")
	}
	if got := unescapeMount(`/run/media/alex/MY\040KEY`); got != "/run/media/alex/MY KEY" {
		t.Errorf("unescape %q", got)
	}
}

func TestBackupAndRestoreOverTheBus(t *testing.T) {
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
	s, _, media, drive := setup(t, "pc-a")
	if err := Export(server, s); err != nil {
		t.Fatal(err)
	}
	server.RequestName(Name, dbus.NameFlagDoNotQueue)
	client, err := dbus.Connect(strings.TrimSpace(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	obj := client.Object(Name, Path)
	var code string
	if err := obj.Call(Iface+".Create", 0, drive, "482915").Store(&code); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(drive, DataDir, "Docs"), 0o755)
	os.WriteFile(filepath.Join(drive, DataDir, "Docs", "plan.txt"), []byte("the plan"), 0o600)
	obj.Call(Iface+".Lock", 0, drive)

	file := filepath.Join(t.TempDir(), "key.sintybackup")
	f, _ := os.Create(file)
	err = obj.Call(Iface+".Backup", 0, drive, "000000", dbus.UnixFD(f.Fd())).Err
	var de dbus.Error
	if !errors.As(err, &de) || de.Name != errorPfx+"WrongPin" {
		t.Fatalf("backup with a wrong PIN: %v", err)
	}
	if err := obj.Call(Iface+".Backup", 0, drive, "482915", dbus.UnixFD(f.Fd())).Err; err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(file); st.Size() == 0 {
		t.Fatal("empty backup")
	}

	fresh := filepath.Join(media, "NEW")
	os.MkdirAll(fresh, 0o755)
	in, _ := os.Open(file)
	err = obj.Call(Iface+".Restore", 0, dbus.UnixFD(in.Fd()), "0000-0000-0000-0000-0000-000", fresh, "1111").Err
	in.Close()
	if !errors.As(err, &de) || de.Name != errorPfx+"WrongCode" {
		t.Fatalf("restore with a wrong code: %v", err)
	}
	in, _ = os.Open(file)
	var next string
	if err := obj.Call(Iface+".Restore", 0, dbus.UnixFD(in.Fd()), code, fresh, "1111").Store(&next); err != nil {
		t.Fatal(err)
	}
	in.Close()
	if next == "" || next == code {
		t.Fatalf("restore must give a new recovery code: %q", next)
	}
	got, err := os.ReadFile(filepath.Join(fresh, DataDir, "Docs", "plan.txt"))
	if err != nil || string(got) != "the plan" {
		t.Fatalf("restored file: %q %v", got, err)
	}
	var mode string
	obj.Call(Iface+".Lock", 0, fresh)
	if err := obj.Call(Iface+".Unlock", 0, fresh, "1111").Store(&mode); err != nil {
		t.Fatalf("unlock restored Key with its new PIN: %v", err)
	}
}

func TestTrustedDevices(t *testing.T) {
	s, _, _, drive := setup(t, "pc-a")
	s.cfg.TrustFile = filepath.Join(t.TempDir(), "trusted.json")
	if _, err := s.Create(drive, "482915"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Devices(); len(list) != 0 {
		t.Fatalf("trusted before remembering: %v", list)
	}
	if err := s.Remember(drive, "482915", ""); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Devices()
	if len(list) != 1 || list[0].Kind != KindKey || list[0].Name != "KEY" || list[0].Added == 0 {
		t.Fatalf("after remembering: %+v", list)
	}
	id := list[0].ID
	s.Lock(drive)
	if mode, err := s.Unlock(drive, "482915"); err != nil || mode != "trusted" {
		t.Fatalf("trusted unlock: %s %v", mode, err)
	}
	if err := s.Revoke(KindKey, "nope"); errName(err) != "Unknown" {
		t.Fatalf("revoke unknown: %v", err)
	}
	if err := s.Revoke(KindKey, id); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Devices(); len(list) != 0 {
		t.Fatalf("after revoke: %v", list)
	}
	s.Lock(drive)
	if _, err := s.Unlock(drive, "482915"); errName(err) != "Copy" {
		t.Fatalf("a revoked Key must not unlock as trusted here: %v", err)
	}
}

func TestForgetHereUntrusts(t *testing.T) {
	s, _, _, drive := setup(t, "pc-a")
	s.cfg.TrustFile = filepath.Join(t.TempDir(), "trusted.json")
	s.Create(drive, "482915")
	s.Remember(drive, "482915", "")
	here, _ := s.cfg.TPM.Fingerprint()
	if err := s.Forget(drive, "482915", here); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Devices(); len(list) != 0 {
		t.Fatalf("after forget: %v", list)
	}
}
