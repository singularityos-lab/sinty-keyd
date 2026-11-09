package service

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type fakeHealth struct {
	ok      bool
	real    uint64
	reports chan []interface{}
}

func (f *fakeHealth) VerifyCapacity(device string) (bool, uint64, *dbus.Error) {
	return f.ok, f.real, nil
}

func (f *fakeHealth) Report(device, check string, ok bool, detail string) *dbus.Error {
	f.reports <- []interface{}{device, check, ok}
	return nil
}

func TestCapacityCheckBeforeErasing(t *testing.T) {
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
	addr = strings.TrimSpace(addr)
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	s, _, _, _ := setup(t, "pc-a")
	s.conn = conn
	s.cfg.SysRoot = t.TempDir()
	block := filepath.Join(s.cfg.SysRoot, "sys/class/block/sdz")
	os.MkdirAll(block, 0o755)
	os.WriteFile(filepath.Join(block, "size"), []byte("8192\n"), 0o644)

	if err := s.checkCapacity("/dev/sdz"); err != nil {
		t.Fatalf("without the health service the drive was refused: %v", err)
	}

	health, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer health.Close()
	fake := &fakeHealth{reports: make(chan []interface{}, 4)}
	health.Export(fake, healthPath, healthIface)
	health.RequestName(healthName, dbus.NameFlagDoNotQueue)

	fake.ok, fake.real = false, 1<<20
	if err := s.checkCapacity("/dev/sdz"); !errors.Is(err, errFakeDrive) {
		t.Fatalf("fake stick: %v", err)
	}
	if fail(errFakeDrive).Name != errorPfx+"FakeDrive" {
		t.Fatalf("error name %s", fail(errFakeDrive).Name)
	}
	fake.ok, fake.real = false, 8192*512
	if err := s.checkCapacity("/dev/sdz"); !errors.Is(err, errDriveWorn) {
		t.Fatalf("damaged stick: %v", err)
	}
	fake.ok = true
	if err := s.checkCapacity("/dev/sdz"); err != nil {
		t.Fatalf("good stick: %v", err)
	}

	s.reportStartup("/dev/sdz", nil)
	s.reportStartup("/dev/sdz", errors.New("download failed"))
	s.reportStartup("/dev/sdz", driveError(errors.New("cp: Input/output error")))
	want := [][]interface{}{{"/dev/sdz", "startup-key", true}, {"/dev/sdz", "startup-key", false}}
	for _, w := range want {
		select {
		case got := <-fake.reports:
			if got[0] != w[0] || got[1] != w[1] || got[2] != w[2] {
				t.Fatalf("report %v, want %v", got, w)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no report for %v", w)
		}
	}
	select {
	case extra := <-fake.reports:
		t.Fatalf("unrelated failure reported: %v", extra)
	case <-time.After(200 * time.Millisecond):
	}
}
