package service

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/sinty-keyd/internal/migrate"
)

func moveSetup(t *testing.T) (*Service, string, *user.User) {
	t.Helper()
	s, _, _, drive := setup(t, "pc-a")
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u := *me
	u.HomeDir = t.TempDir()
	os.MkdirAll(filepath.Join(u.HomeDir, "Pictures"), 0o700)
	os.WriteFile(filepath.Join(u.HomeDir, "Pictures/sea.jpg"), []byte("waves"), 0o600)
	return s, drive, &u
}

func TestMoveHomeNeedsAnOpenKey(t *testing.T) {
	s, drive, u := moveSetup(t)
	if err := s.moveHome(u, drive, MoveToKey); err == nil {
		t.Fatal("moved onto a drive that is not an open Key")
	}
	if _, err := s.Create(drive, "482915"); err != nil {
		t.Fatal(err)
	}
	if err := s.moveHome(u, drive, "sideways"); !errors.Is(err, errMoveDirection) {
		t.Fatalf("direction: %v", err)
	}
	s.Lock(drive)
	if err := s.moveHome(u, drive, MoveToKey); !errors.Is(err, errKeyLocked) {
		t.Fatalf("locked Key: %v", err)
	}
}

func TestMoveHomeToKeyAndBack(t *testing.T) {
	s, drive, u := moveSetup(t)
	if _, err := s.Create(drive, "482915"); err != nil {
		t.Fatal(err)
	}
	var seen []uint32
	s.onProgress = func(dev string, pct uint32) {
		if dev == drive {
			seen = append(seen, pct)
		}
	}
	if err := s.moveHome(u, drive, MoveToKey); err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 || seen[len(seen)-1] != 100 {
		t.Fatalf("progress %v", seen)
	}
	keyHome := filepath.Join(drive, DataDir, "Home")
	if b, err := os.ReadFile(filepath.Join(keyHome, "Pictures/sea.jpg")); err != nil || string(b) != "waves" {
		t.Fatalf("not on the Key: %q %v", b, err)
	}
	m, _ := s.movePlan(u, drive, MoveToKey)
	if migrate.State(m.dst, m.source) != migrate.Verified {
		t.Fatal("not verified")
	}
	if err := s.finishMove(u, drive, MoveToKey, true); err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(u.HomeDir); len(left) != 0 {
		t.Fatalf("computer home not emptied: %v", left)
	}
	if err := s.moveHome(u, drive, MoveFromKey); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(u.HomeDir, "Pictures/sea.jpg")); err != nil || string(b) != "waves" {
		t.Fatalf("not back: %q %v", b, err)
	}
	if err := s.finishMove(u, drive, MoveToKey, true); !errors.Is(err, errNotVerified) {
		t.Fatalf("deleted with the state of another move: %v", err)
	}
	if err := s.finishMove(u, drive, MoveFromKey, false); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(drive, DataDir, "Home/Pictures/sea.jpg")); err != nil || string(b) != "waves" {
		t.Fatal("kept copy on the Key was removed")
	}
	if _, err := os.Stat(filepath.Join(u.HomeDir, migrate.Journal)); !os.IsNotExist(err) {
		t.Fatal("journal left in the home")
	}
}
