package service

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type updatedCall []string

func writeWAL(t *testing.T, rootfs, version string) {
	t.Helper()
	os.MkdirAll(rootfs, 0o755)
	if err := os.WriteFile(filepath.Join(rootfs, "deployment.json"), []byte(`{"rootfs":{"current":"`+version+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeAnchor(t *testing.T, rootfs, version, arch string) {
	t.Helper()
	dir := filepath.Join(rootfs, "release", version)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"version":"`+version+`","arch":"`+arch+`"}`), 0o644)
	for _, f := range []string{"manifest.json.sig", "signing-cert.json", "signing-cert.json.sig"} {
		os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644)
	}
}

func syncSetup(t *testing.T, keyVersion, pcVersion string) (*Service, *fakeMounter, string, *[]updatedCall) {
	t.Helper()
	s, m, sys, _ := presentSetup(t)
	block(t, sys, "sdd1", "sdd", "8:49", true)
	block(t, sys, "sdd2", "sdd", "8:50", true)
	os.Symlink(filepath.Join(sys, "sys/devices/pci0000:00/usb1/sdd"), filepath.Join(sys, "sys/class/block/sdd"))
	os.WriteFile(filepath.Join(sys, "sys/class/block/sdd2/uevent"), []byte("DEVTYPE=partition\nPARTNAME=atom-data\n"), 0o644)
	data, esp := t.TempDir(), t.TempDir()
	writeWAL(t, filepath.Join(data, "boot/rootfs"), keyVersion)
	os.MkdirAll(filepath.Join(esp, "EFI/atom"), 0o755)
	m.disks["sdd1"], m.disks["sdd2"] = esp, data
	m.nums["sdd1"], m.nums["sdd2"] = "8:49", "8:50"
	writeWAL(t, filepath.Join(sys, "boot/rootfs"), pcVersion)
	calls := &[]updatedCall{}
	s.cfg.CacheDir = filepath.Join(sys, "var/cache/sinty-keyd")
	s.cfg.Updated = func(onLine func(string), args ...string) error {
		*calls = append(*calls, args)
		if onLine != nil {
			onLine("progress 50")
		}
		return nil
	}
	return s, m, sys, calls
}

func (s *Service) keyRootfs(m *fakeMounter) string {
	return filepath.Join(m.disks["sdd2"], "boot/rootfs")
}

func TestSyncUpdatesOlderKey(t *testing.T) {
	s, m, sys, calls := syncSetup(t, "v3", "v5")
	writeAnchor(t, filepath.Join(sys, "boot/rootfs"), "v5", "")
	writeAnchor(t, s.keyRootfs(m), "v3", "x86_64")
	d, err := s.startupDrive("/dev/sdd")
	if err != nil {
		t.Fatal(err)
	}
	data, esp, done, err := s.mountStartup(d, true)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.syncState(data, esp)
	done()
	if err != nil || st.direction != SyncKey || st.keyVersion != "v3" || st.pcVersion != "v5" {
		t.Fatalf("state %+v %v", st, err)
	}
	var pct []uint32
	s.onProgress = func(_ string, p uint32) { pct = append(pct, p) }
	if derr := s.syncStartup("/dev/sdd", SyncKey); derr != nil {
		t.Fatal(derr)
	}
	if len(*calls) != 2 || (*calls)[0][0] != "export-release" || (*calls)[1][0] != "stage-from" {
		t.Fatalf("calls %v", *calls)
	}
	stage := (*calls)[1]
	if !slices.Contains(stage, "--target") || !slices.Contains(stage, filepath.Join(s.cfg.PeekDir, "startup/data/boot/rootfs/deployment.json")) ||
		!slices.Contains(stage, filepath.Join(s.cfg.PeekDir, "startup/esp/EFI/atom")) {
		t.Fatalf("stage-from %v", stage)
	}
	if m.ro[filepath.Join(s.cfg.PeekDir, "startup/data")] {
		t.Fatal("Key mounted read-only for its update")
	}
	if len(m.mounts) != 0 {
		t.Fatalf("left mounted: %v", m.mounts)
	}
	if !slices.Contains(pct, 50) || pct[len(pct)-1] != 100 {
		t.Fatalf("progress %v", pct)
	}
	entries, _ := os.ReadDir(s.cfg.CacheDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "export-") {
			t.Fatalf("export dir left: %s", e.Name())
		}
	}
	if derr := s.syncStartup("/dev/sdd", SyncComputer); derr == nil {
		t.Fatal("the wrong direction ran")
	}
}

func TestSyncUpdatesOlderComputer(t *testing.T) {
	s, m, _, calls := syncSetup(t, "v7", "v5")
	writeAnchor(t, s.keyRootfs(m), "v7", "x86_64")
	if derr := s.syncStartup("/dev/sdd", SyncComputer); derr != nil {
		t.Fatal(derr)
	}
	export, stage := (*calls)[0], (*calls)[1]
	if !slices.Contains(export, filepath.Join(s.cfg.PeekDir, "startup/data/boot/rootfs")) || slices.Contains(stage, "--target") || slices.Contains(stage, "--wal") {
		t.Fatalf("calls %v", *calls)
	}
	if !m.ro[filepath.Join(s.cfg.PeekDir, "startup/data")] {
		t.Fatal("Key mounted writable to update the computer")
	}
}

func TestSyncRefuses(t *testing.T) {
	s, m, sys, calls := syncSetup(t, "v3", "v5")
	if derr := s.syncStartup("/dev/sdd", SyncKey); derr == nil {
		t.Fatal("updated the Key without a signed release here")
	}
	writeAnchor(t, filepath.Join(sys, "boot/rootfs"), "v5", "")
	writeAnchor(t, s.keyRootfs(m), "v3", "aarch64")
	if derr := s.syncStartup("/dev/sdd", SyncKey); derr == nil {
		t.Fatal("updated a Key of another architecture")
	}
	writeAnchor(t, s.keyRootfs(m), "v3", "x86_64")
	if derr := s.syncStartup("/dev/sdb", SyncKey); derr == nil {
		t.Fatal("a plain Sinty Key taken for a startup Key")
	}
	if len(*calls) != 0 {
		t.Fatalf("updated ran: %v", *calls)
	}
	s.cfg.Updated = func(func(string), ...string) error { return errors.New("updated: stage-from: manifest signature invalid") }
	if derr := s.syncStartup("/dev/sdd", SyncKey); derr == nil || !strings.Contains(derr.Error(), "signature") {
		t.Fatalf("failure hidden: %v", derr)
	}
	if len(m.mounts) != 0 {
		t.Fatalf("left mounted after failure: %v", m.mounts)
	}
}

func TestPEArch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.efi")
	b := make([]byte, 0x90)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0xaa64)
	os.WriteFile(p, b, 0o644)
	if peArch(p) != "aarch64" {
		t.Fatal(peArch(p))
	}
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	os.WriteFile(p, b, 0o644)
	if peArch(p) != "x86_64" {
		t.Fatal(peArch(p))
	}
}
