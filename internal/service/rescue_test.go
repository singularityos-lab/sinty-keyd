package service

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func rescueSetup(t *testing.T, script string) (*Service, string, *user.User) {
	t.Helper()
	s, m, sys, _ := presentSetup(t)
	block(t, sys, "sdb2", "sdb", "8:18", true)
	block(t, sys, "nvme1n1p1", "nvme1n1", "259:5", false)
	block(t, sys, "nvme1n1p2", "nvme1n1", "259:6", false)
	os.WriteFile(filepath.Join(sys, "sys/class/block/nvme1n1p2/uevent"), []byte("DEVTYPE=partition\nPARTNAME=atom-data\n"), 0o644)
	os.WriteFile(filepath.Join(sys, "sys/class/block/sdb2/uevent"), []byte("DEVTYPE=partition\nPARTNAME=atom-data\n"), 0o644)
	for disk, dir := range map[string]string{"sdb": "usb1", "nvme0n1": "nvme", "nvme1n1": "nvme"} {
		os.Symlink(filepath.Join(sys, "sys/devices/pci0000:00", dir, disk), filepath.Join(sys, "sys/class/block", disk))
	}
	os.WriteFile(filepath.Join(sys, "sys/devices/pci0000:00/nvme/nvme1n1/size"), []byte("1000\n"), 0o644)
	os.WriteFile(m.info, []byte("22 1 8:18 / /var rw - f2fs /dev/sdb2 rw\n"), 0o644)
	os.MkdirAll(filepath.Join(sys, "proc"), 0o755)
	os.WriteFile(filepath.Join(sys, "proc/cmdline"), []byte("quiet sing.portable=1\n"), 0o644)
	bin := filepath.Join(t.TempDir(), "sinty-rescue")
	os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o755)
	s.cfg.Rescue = bin
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u := *me
	u.HomeDir = t.TempDir()
	return s, sys, &u
}

func TestRescueTargets(t *testing.T) {
	s, sys, _ := rescueSetup(t, "exit 0\n")
	got := s.rescueTargets()
	if len(got) != 1 || got[0].Device != "/dev/nvme1n1" || got[0].Size != 512000 || got[0].Name != "Internal Drive" {
		t.Fatalf("targets %+v", got)
	}
	os.WriteFile(filepath.Join(sys, "proc/cmdline"), []byte("quiet\n"), 0o644)
	if got := s.rescueTargets(); len(got) != 0 {
		t.Fatalf("rescue offered without a Key boot: %+v", got)
	}
}

func TestRescueStartsOnTheComputerDrive(t *testing.T) {
	args := filepath.Join(t.TempDir(), "args")
	s, sys, u := rescueSetup(t, "echo \"$@\" > "+args+"\n: > \"$5\"\nexec sleep 30\n")
	if _, err := s.startRescue(u, "/dev/sdb"); !errors.Is(err, errNoTarget) {
		t.Fatalf("the Key itself was rescued: %v", err)
	}
	sock, err := s.startRescue(u, "/dev/nvme1n1")
	if err != nil {
		t.Fatal(err)
	}
	if sock != filepath.Join(sys, "run/sinty-rescue/recovery.sock") {
		t.Fatalf("socket %s", sock)
	}
	b, _ := os.ReadFile(args)
	want := "/dev/nvme1n1p2 /dev/nvme1n1p1 /dev/sdb1 " + filepath.Join(u.HomeDir, "Rescued") + " " + sock
	if strings.TrimSpace(string(b)) != want {
		t.Fatalf("args %q want %q", b, want)
	}
	if st, err := os.Stat(filepath.Join(u.HomeDir, "Rescued")); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("rescue folder %v %v", st, err)
	}
	if _, err := s.startRescue(u, "/dev/nvme1n1"); !errors.Is(err, errRescueBusy) {
		t.Fatalf("second rescue: %v", err)
	}
	if err := s.endRescue(uid(u) + 1); !errors.Is(err, errNotYours) {
		t.Fatalf("someone else ended it: %v", err)
	}
	if err := s.endRescue(uid(u)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		gone := s.rescue == nil
		s.mu.Unlock()
		if gone {
			if _, err := os.Stat(sock); !os.IsNotExist(err) {
				t.Fatalf("socket left behind: %v", err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("rescue still running after it was ended")
}

func TestRescueThatFailsToStart(t *testing.T) {
	s, _, u := rescueSetup(t, "exit 1\n")
	if _, err := s.startRescue(u, "/dev/nvme1n1"); err == nil {
		t.Fatal("a failed launcher reported success")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rescue != nil {
		t.Fatal("a failed rescue stays registered")
	}
}

func uid(u *user.User) int {
	n, _ := strconv.Atoi(u.Uid)
	return n
}
