package service

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/key"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

type fakeMounter struct {
	info   string
	nums   map[string]string
	disks  map[string]string
	ro     map[string]bool
	mounts map[string]string
}

func (f *fakeMounter) Mount(dev, dir, opts string, readOnly bool) error {
	src, ok := f.disks[filepath.Base(dev)]
	if !ok {
		return errors.New("no filesystem")
	}
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		return err
	}
	f.ro[dir] = readOnly
	f.mounts[dir] = src
	if !readOnly && f.info != "" {
		line := "40 1 " + f.nums[filepath.Base(dev)] + " / " + strings.ReplaceAll(dir, " ", `\040`) + " rw - ext4 " + dev + " rw\n"
		fh, err := os.OpenFile(f.info, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer fh.Close()
		fh.WriteString(line)
	}
	return nil
}

func (f *fakeMounter) Unmount(dir string) error {
	if _, ok := f.mounts[dir]; !ok {
		return errors.New("not mounted")
	}
	delete(f.mounts, dir)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func block(t *testing.T, sys, name, parent, num string, removable bool) {
	t.Helper()
	disk := filepath.Join(sys, "sys/devices/pci0000:00/usb1", parent)
	if !removable {
		disk = filepath.Join(sys, "sys/devices/pci0000:00/nvme", parent)
	}
	os.MkdirAll(disk, 0o755)
	r := "0"
	if removable {
		r = "1"
	}
	os.WriteFile(filepath.Join(disk, "removable"), []byte(r+"\n"), 0o644)
	part := filepath.Join(disk, name)
	os.MkdirAll(part, 0o755)
	os.WriteFile(filepath.Join(part, "partition"), []byte("1\n"), 0o644)
	os.WriteFile(filepath.Join(part, "dev"), []byte(num+"\n"), 0o644)
	cls := filepath.Join(sys, "sys/class/block")
	os.MkdirAll(cls, 0o755)
	os.Symlink(part, filepath.Join(cls, name))
}

func presentSetup(t *testing.T) (*Service, *fakeMounter, string, string) {
	t.Helper()
	sys := t.TempDir()
	keyDisk := t.TempDir()
	plain := t.TempDir()
	if _, _, err := key.CreateFor(keyDisk, "482915", "alex"); err != nil {
		t.Fatal(err)
	}
	block(t, sys, "sdb1", "sdb", "8:17", true)
	block(t, sys, "sdc1", "sdc", "8:33", true)
	block(t, sys, "nvme0n1p1", "nvme0n1", "259:1", false)
	info := filepath.Join(t.TempDir(), "mountinfo")
	os.WriteFile(info, []byte("22 1 259:1 / / rw - ext4 /dev/nvme0n1p1 rw\n"), 0o644)
	m := &fakeMounter{info: info, nums: map[string]string{"sdb1": "8:17", "sdc1": "8:33"}, disks: map[string]string{"sdb1": keyDisk, "sdc1": plain, "nvme0n1p1": keyDisk}, ro: map[string]bool{}, mounts: map[string]string{}}
	s := New(Config{
		TPM: tpm.NewFake("pc-a"), Crypt: newCrypt(), SysRoot: sys, MountInfo: info,
		PeekDir: filepath.Join(sys, "run/sinty-keyd/peek"), Mounter: m,
		Mounts: []string{filepath.Join(sys, "run/media") + "/"},
	})
	return s, m, sys, keyDisk
}

func TestScanFindsOnlyRemovableKeys(t *testing.T) {
	s, m, _, _ := presentSetup(t)
	s.Scan()
	got := s.Present()
	if len(got) != 1 || got[0].Device != "/dev/sdb1" || got[0].Owner != "alex" || got[0].State != StateLocked {
		t.Fatalf("present: %+v", got)
	}
	if len(m.mounts) != 0 {
		t.Fatalf("peek left mounts behind: %v", m.mounts)
	}
}

func TestScanReportsOlderCopy(t *testing.T) {
	s, _, _, keyDisk := presentSetup(t)
	fake := s.cfg.TPM
	k, _ := key.Open(keyDisk)
	if err := k.Remember(fake, "482915", "desk", ""); err != nil {
		t.Fatal(err)
	}
	old := t.TempDir()
	data, _ := os.ReadFile(filepath.Join(keyDisk, ".sinty-key", "key.json"))
	os.MkdirAll(filepath.Join(old, ".sinty-key"), 0o700)
	os.WriteFile(filepath.Join(old, ".sinty-key", "key.json"), data, 0o600)
	k, _ = key.Open(keyDisk)
	if _, _, err := k.Unlock(fake, "482915"); err != nil {
		t.Fatal(err)
	}
	s.cfg.Mounter.(*fakeMounter).disks["sdb1"] = old
	s.Scan()
	if got := s.Present(); len(got) != 1 || got[0].State != StateCopy {
		t.Fatalf("older copy not reported: %+v", got)
	}
}

func TestOwnerOf(t *testing.T) {
	for in, want := range map[string]string{"/run/media/alex/KEY": "alex", "/run/media/alex": "alex", "/media/KEY": "", "/mnt/x": ""} {
		if got := ownerOf(in); got != want {
			t.Fatalf("%s: %q", in, got)
		}
	}
}

func TestAttachOverTheBus(t *testing.T) {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
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
	s, m, sys, _ := presentSetup(t)
	if err := Export(server, s); err != nil {
		t.Fatal(err)
	}
	server.RequestName(Name, dbus.NameFlagDoNotQueue)
	s.Scan()
	client, err := dbus.Connect(strings.TrimSpace(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	obj := client.Object(Name, Path)

	var present []PresentKey
	if err := obj.StoreProperty(Iface+".Present", &present); err != nil || len(present) != 1 || present[0].Owner != "alex" {
		t.Fatalf("present property: %+v %v", present, err)
	}

	var root, mode string
	err = obj.Call(Iface+".Attach", 0, "/dev/sdb1", me.Username, "482915").Store(&root, &mode)
	var de dbus.Error
	if !errors.As(err, &de) || de.Name != errorPfx+"NotAllowed" {
		t.Fatalf("attach by a stranger: %v", err)
	}

	s.cfg.AttachUsers = []string{me.Username}
	err = obj.Call(Iface+".Attach", 0, "/dev/sdb1", me.Username, "000000").Store(&root, &mode)
	if !errors.As(err, &de) || de.Name != errorPfx+"WrongPin" {
		t.Fatalf("attach with a wrong PIN: %v", err)
	}
	attached := ""
	for dir := range m.mounts {
		if strings.HasPrefix(dir, filepath.Join(sys, "run/media", me.Username)+"/") {
			attached = dir
		}
	}
	if attached == "" || m.ro[attached] {
		t.Fatalf("not mounted writable for the user after a wrong PIN: %v", m.mounts)
	}
	if err := obj.Call(Iface+".Attach", 0, "/dev/sdb1", me.Username, "482915").Store(&root, &mode); err != nil || mode != "guest" {
		t.Fatalf("attach: %s %s %v", root, mode, err)
	}
	var unlockedList []string
	if err := obj.StoreProperty(Iface+".Unlocked", &unlockedList); err != nil || len(unlockedList) != 1 {
		t.Fatalf("unlocked: %v %v", unlockedList, err)
	}
}

func TestStalePeekMountIsSweptAndNotSystem(t *testing.T) {
	s, m, sys, _ := presentSetup(t)
	stale := filepath.Join(sys, "run/sinty-keyd/peek/sdc1")
	os.MkdirAll(stale, 0o700)
	m.mounts[stale] = "x"
	fh, _ := os.OpenFile(s.cfg.MountInfo, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString("41 1 8:33 / " + stale + " ro - ext4 /dev/sdc1 ro\n")
	fh.Close()
	if !strings.HasPrefix(stale, s.cfg.PeekDir+"/") {
		t.Fatal("bad fixture")
	}
	mounted, _ := s.devNumbers()
	if root := mounted["8:33"]; root != stale {
		t.Fatalf("fixture mount: %q", root)
	}
	s.Scan()
	if _, ok := m.mounts[stale]; ok {
		t.Fatal("stale peek mount was not swept")
	}
}

func TestPeekMountDoesNotHideDrive(t *testing.T) {
	s, _, sys, _ := presentSetup(t)
	disk := filepath.Join(sys, "sys/devices/pci0000:00/usb1/sdc")
	os.WriteFile(filepath.Join(disk, "size"), []byte("15240000\n"), 0o644)
	os.Symlink(disk, filepath.Join(sys, "sys/class/block/sdc"))
	peek := filepath.Join(s.cfg.PeekDir, "sdc1")
	fh, _ := os.OpenFile(s.cfg.MountInfo, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString("41 1 8:33 / " + peek + " ro - ext4 /dev/sdc1 ro\n")
	fh.Close()
	list, err := s.drives()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range list {
		if d.Device == "/dev/sdc" {
			return
		}
	}
	t.Fatalf("drive with a peek mount was hidden: %+v", list)
}

func TestDriveErrorNamesWornDrive(t *testing.T) {
	io := errors.New("atom-install: dd if=/dev/nvme0n1p1 of=/dev/sdc1 bs=4M conv=fsync: exit status 1: dd: IO error: Input/output error")
	if driveError(io) != errDriveWorn {
		t.Fatalf("I/O error not mapped: %v", driveError(io))
	}
	other := errors.New("sfdisk: no space")
	if driveError(other) != other {
		t.Fatal("unrelated error rewritten")
	}
}

func TestStartupKeyAndOpticalDrive(t *testing.T) {
	s, _, sys, _ := presentSetup(t)
	disk := filepath.Join(sys, "sys/devices/pci0000:00/usb1/sdc")
	os.WriteFile(filepath.Join(disk, "size"), []byte("15240000\n"), 0o644)
	os.WriteFile(filepath.Join(disk, "sdc1", "uevent"), []byte("MAJOR=8\nMINOR=33\nDEVNAME=sdc1\nPARTNAME=atom-data\n"), 0o644)
	os.Symlink(disk, filepath.Join(sys, "sys/class/block/sdc"))
	sr := filepath.Join(sys, "sys/devices/pci0000:00/ata1/sr0")
	os.MkdirAll(sr, 0o755)
	os.WriteFile(filepath.Join(sr, "removable"), []byte("1\n"), 0o644)
	os.WriteFile(filepath.Join(sr, "size"), []byte("2097152\n"), 0o644)
	os.Symlink(sr, filepath.Join(sys, "sys/class/block/sr0"))
	list, err := s.drives()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range list {
		if d.Device == "/dev/sr0" {
			t.Fatal("optical drive offered as a Key target")
		}
		if d.Device == "/dev/sdc" {
			found = true
			if !d.Startup {
				t.Fatalf("startup key not recognised: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("startup key missing: %+v", list)
	}
}

func TestUnreadableMountedKeyIsStillPresent(t *testing.T) {
	s, _, sys, _ := presentSetup(t)
	root := filepath.Join(sys, "run/media/alex/SINTYKEY")
	os.MkdirAll(filepath.Join(root, ".sinty-key", "key.json"), 0o755)
	fh, _ := os.OpenFile(s.cfg.MountInfo, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString("41 1 8:17 / " + root + " rw - ext4 /dev/sdb1 rw\n")
	fh.Close()
	s.Scan()
	for _, p := range s.Present() {
		if p.Device == "/dev/sdb1" {
			return
		}
	}
	t.Fatalf("key mounted elsewhere but unreadable was dropped: %+v", s.Present())
}

func TestDriveErrorNamesGoIOError(t *testing.T) {
	err := errors.New("atom-install: write /dev/sdc1: input/output error")
	if driveError(err) != errDriveWorn {
		t.Fatalf("Go I/O error not mapped: %v", driveError(err))
	}
}
