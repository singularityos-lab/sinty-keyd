package badge

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPolicy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sinty", "key-badge")
	if !Allowed(p) {
		t.Fatal("allowed by default")
	}
	if err := SetAllowed(p, false); err != nil || Allowed(p) {
		t.Fatalf("turned off: %v", err)
	}
	if err := SetAllowed(p, true); err != nil || !Allowed(p) {
		t.Fatalf("turned on: %v", err)
	}
}

func put(t *testing.T, path, data string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerified(t *testing.T) {
	sys := t.TempDir()
	hash := strings.Repeat("ab", 32)
	put(t, filepath.Join(sys, "proc/cmdline"), "quiet sing.roothash="+hash+" lockdown=integrity\n")
	put(t, filepath.Join(sys, "sys/kernel/security/lockdown"), "none [integrity] confidentiality\n")
	put(t, filepath.Join(sys, "sys/block/dm-0/dm/uuid"), "CRYPT-VERITY-1234-root\n")
	if err := Verified(sys); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(sys, "sys/kernel/security/lockdown"), "[none] integrity confidentiality\n")
	if err := Verified(sys); !errors.Is(err, ErrUnverified) {
		t.Fatalf("lockdown off: %v", err)
	}
	put(t, filepath.Join(sys, "sys/kernel/security/lockdown"), "none integrity [confidentiality]\n")
	put(t, filepath.Join(sys, "sys/block/dm-0/dm/uuid"), "CRYPT-LUKS2-1234-data\n")
	if err := Verified(sys); !errors.Is(err, ErrUnverified) {
		t.Fatalf("no verity: %v", err)
	}
	put(t, filepath.Join(sys, "sys/block/dm-0/dm/uuid"), "CRYPT-VERITY-1234-root\n")
	put(t, filepath.Join(sys, "proc/cmdline"), "quiet\n")
	if err := Verified(sys); !errors.Is(err, ErrUnverified) {
		t.Fatalf("no root hash: %v", err)
	}
}

func TestAccount(t *testing.T) {
	etc := t.TempDir()
	put(t, filepath.Join(etc, "passwd"), "root:x:0:0:root:/root:/bin/bash\nalex:x:1000:1000:Alex:/home/alex:/bin/bash\n")
	put(t, filepath.Join(etc, "group"), "root:x:0:\nalex:x:1000:\n")
	put(t, filepath.Join(etc, "shadow"), "root:!:1::::::\nalex:$6$x:1::::::\n")
	os.Chmod(filepath.Join(etc, "shadow"), 0o600)
	if err := AddAccount(etc, "Sam: Doe\n"); err != nil {
		t.Fatal(err)
	}
	if err := AddAccount(etc, "Sam"); err != nil {
		t.Fatal(err)
	}
	pw, _ := os.ReadFile(filepath.Join(etc, "passwd"))
	want := "sinty-badge:x:" + strconv.Itoa(UID) + ":" + strconv.Itoa(UID) + ":Sam:" + Home + ":" + Shell
	if strings.Count(string(pw), "sinty-badge:") != 1 || !strings.Contains(string(pw), want) || !strings.Contains(string(pw), "alex:x:1000") {
		t.Fatalf("passwd:\n%s", pw)
	}
	st, _ := os.Stat(filepath.Join(etc, "shadow"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("shadow mode %v", st.Mode())
	}
	sh, _ := os.ReadFile(filepath.Join(etc, "shadow"))
	if !strings.Contains(string(sh), "sinty-badge:*:") || !strings.Contains(string(sh), "alex:$6$x") {
		t.Fatalf("shadow:\n%s", sh)
	}
	if err := RemoveAccount(etc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"passwd", "group", "shadow"} {
		data, _ := os.ReadFile(filepath.Join(etc, name))
		if strings.Contains(string(data), "sinty-badge") || !strings.Contains(string(data), "alex") {
			t.Fatalf("%s after removal:\n%s", name, data)
		}
	}
	put(t, filepath.Join(etc, "passwd"), "other:x:"+strconv.Itoa(UID)+":100::/home/other:/bin/sh\n")
	if err := AddAccount(etc, "Sam"); !errors.Is(err, ErrTaken) {
		t.Fatalf("uid taken: %v", err)
	}
}

func TestTicket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "badge", "ticket")
	a, err := NewTicket(path)
	if err != nil || len(a) != 64 {
		t.Fatalf("ticket %q %v", a, err)
	}
	b, _ := NewTicket(path)
	data, _ := os.ReadFile(path)
	st, _ := os.Stat(path)
	if a == b || strings.TrimSpace(string(data)) != b || st.Mode().Perm() != 0o600 {
		t.Fatalf("ticket file %q mode %v", data, st.Mode())
	}
}

func TestProcesses(t *testing.T) {
	proc := t.TempDir()
	put(t, filepath.Join(proc, "12/status"), "Name:\tbash\nUid:\t61000\t61000\t61000\t61000\n")
	put(t, filepath.Join(proc, "13/status"), "Name:\tsh\nUid:\t1000\t1000\t1000\t1000\n")
	put(t, filepath.Join(proc, "self/status"), "Uid:\t61000\n")
	got := Processes(proc, UID)
	if len(got) != 1 || got[0] != 12 {
		t.Fatalf("processes %v", got)
	}
}
