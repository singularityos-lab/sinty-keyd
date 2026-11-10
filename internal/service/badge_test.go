package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-keyd/internal/badge"
)

type mapCall struct {
	src, dst string
	uid, gid int
}

func badgeSetup(t *testing.T) (*Service, *fakeMounter, string, *[]mapCall) {
	t.Helper()
	s, m, sys, _ := presentSetup(t)
	etc := filepath.Join(sys, "etc")
	os.MkdirAll(etc, 0o755)
	os.WriteFile(filepath.Join(etc, "passwd"), []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644)
	os.WriteFile(filepath.Join(etc, "group"), []byte("root:x:0:\n"), 0o644)
	os.WriteFile(filepath.Join(etc, "shadow"), []byte("root:!:1::::::\n"), 0o600)
	calls := &[]mapCall{}
	s.cfg.Verify = func(string) error { return nil }
	s.cfg.MapHome = func(src, dst string, _, _, uid, gid int) error {
		*calls = append(*calls, mapCall{src, dst, uid, gid})
		return nil
	}
	s.cfg.BadgeGrace = 50 * time.Millisecond
	s.Scan()
	return s, m, sys, calls
}

func hasAccount(t *testing.T, sys string) bool {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(sys, "etc/passwd"))
	return strings.Contains(string(data), badge.User+":")
}

func TestBadgeOpensAndEnds(t *testing.T) {
	s, m, sys, calls := badgeSetup(t)
	user, ticket, err := s.openBadge("/dev/sdb1", "482915")
	if err != nil {
		t.Fatal(err)
	}
	if user != badge.User || len(ticket) != 64 {
		t.Fatalf("badge %q %q", user, ticket)
	}
	data, _ := os.ReadFile(filepath.Join(sys, "run/sinty-badge/ticket"))
	if strings.TrimSpace(string(data)) != ticket {
		t.Fatalf("ticket file %q", data)
	}
	if !hasAccount(t, sys) {
		t.Fatal("no badge account")
	}
	pw, _ := os.ReadFile(filepath.Join(sys, "etc/passwd"))
	if !strings.Contains(string(pw), ":alex:"+badge.Home+":") {
		t.Fatalf("passwd %s", pw)
	}
	root := s.badgeRoot()
	if len(*calls) != 1 || (*calls)[0].src != filepath.Join(root, DataDir, "Home") || (*calls)[0].dst != filepath.Join(sys, badge.Home) || (*calls)[0].uid != badge.UID {
		t.Fatalf("map %+v", *calls)
	}
	if _, ok := m.mounts[root]; !ok {
		t.Fatal("key not mounted")
	}
	if s.badge == nil || s.badge.id == "" {
		t.Fatal("no badge session")
	}
	if _, _, err := s.openBadge("/dev/sdb1", "482915"); !errors.Is(err, errBadgeBusy) {
		t.Fatalf("second badge: %v", err)
	}
	if derr := s.endBadge(false); derr != nil {
		t.Fatal(derr)
	}
	if hasAccount(t, sys) {
		t.Fatal("account left behind")
	}
	if _, ok := m.mounts[root]; ok {
		t.Fatal("key still mounted")
	}
	if _, err := os.Stat(filepath.Join(sys, "run/sinty-badge/ticket")); !os.IsNotExist(err) {
		t.Fatal("ticket left behind")
	}
	if derr := s.endBadge(false); derr == nil {
		t.Fatal("ending twice")
	}
}

func TestBadgeRefused(t *testing.T) {
	s, m, sys, _ := badgeSetup(t)
	if err := badge.SetAllowed(s.cfg.BadgePolicy, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.openBadge("/dev/sdb1", "482915"); !errors.Is(err, errBadgeOff) {
		t.Fatalf("policy off: %v", err)
	}
	badge.SetAllowed(s.cfg.BadgePolicy, true)
	s.cfg.Verify = func(string) error { return badge.ErrUnverified }
	if _, _, err := s.openBadge("/dev/sdb1", "482915"); !errors.Is(err, badge.ErrUnverified) {
		t.Fatalf("unverified: %v", err)
	}
	s.cfg.Verify = func(string) error { return nil }
	if _, _, err := s.openBadge("/dev/sdb1", "000000"); err == nil {
		t.Fatal("wrong PIN accepted")
	}
	if hasAccount(t, sys) || len(m.mounts) != 0 || s.badge != nil {
		t.Fatalf("wrong PIN left state: account=%v mounts=%v", hasAccount(t, sys), m.mounts)
	}
	if _, _, err := s.openBadge("/dev/sdc1", "482915"); err == nil {
		t.Fatal("plain disk accepted")
	}
}

func TestBadgeKeyRemoved(t *testing.T) {
	s, m, sys, _ := badgeSetup(t)
	if _, _, err := s.openBadge("/dev/sdb1", "482915"); err != nil {
		t.Fatal(err)
	}
	s.watchBadge(nil)
	if s.badge == nil || !s.badge.removed {
		t.Fatal("removal not noticed")
	}
	if !hasAccount(t, sys) {
		t.Fatal("ended before the grace period")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		done := s.badge == nil
		s.mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.badge != nil || hasAccount(t, sys) || len(m.mounts) != 0 {
		t.Fatalf("not ended after the grace period: mounts=%v", m.mounts)
	}
}

func TestBadgeKeyReturned(t *testing.T) {
	s, _, sys, calls := badgeSetup(t)
	s.cfg.BadgeGrace = time.Hour
	if _, _, err := s.openBadge("/dev/sdb1", "482915"); err != nil {
		t.Fatal(err)
	}
	s.watchBadge(nil)
	if derr := s.resumeBadge("000000"); derr == nil {
		t.Fatal("wrong PIN resumed")
	}
	if derr := s.resumeBadge("482915"); derr != nil {
		t.Fatal(derr)
	}
	if s.badge == nil || s.badge.removed || s.badge.gone != nil {
		t.Fatal("session not resumed")
	}
	if len(*calls) < 2 {
		t.Fatalf("home not remapped: %+v", *calls)
	}
	if !hasAccount(t, sys) {
		t.Fatal("account dropped")
	}
	s.endBadge(false)
}
