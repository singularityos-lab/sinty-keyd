package service

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeyForAnotherArchReportsOneProgressBar(t *testing.T) {
	dir := t.TempDir()
	fetch := script(t, dir, "fetch", "echo 'file 1 3 loader.efi'\necho 'file 2 3 kernelcache.efi'\necho 'file 3 3 rootfs.erofs'\necho 'progress 0'\necho 'progress 50'\necho 'progress 100'\necho 'release v9 aarch64'\n")
	install := script(t, dir, "install", "echo 'progress 0'\necho 'progress 50'\necho 'progress 100'\n")
	s := New(Config{})
	var got []uint32
	s.onProgress = func(dev string, pct uint32) {
		if dev != "/dev/sdz" {
			t.Fatalf("progress for %s", dev)
		}
		got = append(got, pct)
	}
	if err := s.runSteps("/dev/sdz", keyStep(0, 50, fetch), keyStep(50, 50, install)); err != nil {
		t.Fatal(err)
	}
	want := []uint32{0, 2, 5, 27, 50, 50, 75, 100}
	if !slices.Equal(got, want) {
		t.Fatalf("progress %v, want %v", got, want)
	}
}

func TestFailedStepStopsAndNamesTheTool(t *testing.T) {
	dir := t.TempDir()
	fetch := script(t, dir, "updated", "echo 'manifest: built for x86_64, this computer is aarch64' >&2\nexit 1\n")
	install := script(t, dir, "atom-install", "touch "+filepath.Join(dir, "ran")+"\n")
	s := New(Config{})
	err := s.runSteps("/dev/sdz", keyStep(0, 50, fetch), keyStep(50, 50, install))
	if err == nil || !strings.Contains(err.Error(), "updated: manifest: built for x86_64") {
		t.Fatalf("error %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); !os.IsNotExist(err) {
		t.Fatal("install ran after the download failed")
	}
}

func TestArchitecturesListsThisComputerFirst(t *testing.T) {
	got, derr := New(Config{}).Architectures()
	if derr != nil || len(got) != 2 || got[0] != localArch() || got[0] == got[1] {
		t.Fatalf("%v %v", got, derr)
	}
}

func TestUnknownArchitectureIsRefused(t *testing.T) {
	if derr := New(Config{}).MakeBootableFor("", "/dev/sdz", "riscv64"); derr == nil {
		t.Fatal("riscv64 accepted")
	}
}
