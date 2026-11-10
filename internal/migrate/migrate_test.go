package migrate

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func me() Owner {
	return Owner{UID: os.Getuid(), GID: os.Getgid()}
}

func home(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "Documents/deep"), 0o755)
	os.MkdirAll(filepath.Join(src, ".cache/thumbs"), 0o700)
	os.WriteFile(filepath.Join(src, "Documents/deep/note.txt"), []byte("hello"), 0o640)
	os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(src, "empty"), nil, 0o600)
	os.WriteFile(filepath.Join(src, ".cache/thumbs/a.png"), []byte("cache"), 0o600)
	os.Symlink("Documents/deep/note.txt", filepath.Join(src, "link"))
	os.Symlink("/etc/passwd", filepath.Join(src, "outside"))
	big := make([]byte, 3<<20)
	for i := range big {
		big[i] = byte(i)
	}
	os.WriteFile(filepath.Join(src, "Documents/big.bin"), big, 0o600)
	return src
}

func TestCopyAndVerify(t *testing.T) {
	src, dst := home(t), t.TempDir()
	var last, total int64
	if err := Copy(src, dst, "to-key", me(), func(d, tot int64) { last, total = d, tot }); err != nil {
		t.Fatal(err)
	}
	if last != total || total != int64(5+10+3<<20) {
		t.Fatalf("progress %d of %d", last, total)
	}
	if State(dst, "to-key") != Copying || State(dst, "from-key") != "" {
		t.Fatalf("state %q", State(dst, "to-key"))
	}
	b, err := os.ReadFile(filepath.Join(dst, "Documents/deep/note.txt"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("note %q %v", b, err)
	}
	if st, _ := os.Stat(filepath.Join(dst, "run.sh")); st.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", st.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(dst, "outside")); l != "/etc/passwd" {
		t.Fatalf("absolute link followed or lost: %q", l)
	}
	if _, err := os.Stat(filepath.Join(dst, ".cache")); !os.IsNotExist(err) {
		t.Fatal("cache copied")
	}
	si, _ := os.Stat(filepath.Join(src, "Documents/big.bin"))
	di, _ := os.Stat(filepath.Join(dst, "Documents/big.bin"))
	if !si.ModTime().Equal(di.ModTime()) {
		t.Fatal("modification time not kept")
	}
	if err := Verify(src, dst, "to-key", nil); err != nil {
		t.Fatal(err)
	}
	if State(dst, "to-key") != Verified {
		t.Fatal("not marked verified")
	}
}

func inode(t *testing.T, p string) uint64 {
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Ino
}

func TestCopyResumes(t *testing.T) {
	src, dst := home(t), t.TempDir()
	os.MkdirAll(filepath.Join(dst, "Documents/deep"), 0o700)
	os.WriteFile(filepath.Join(dst, "Documents/big.bin"), []byte("half"), 0o600)
	os.WriteFile(filepath.Join(dst, "Documents/big.bin.sinty-part"), []byte("torn"), 0o600)
	os.WriteFile(filepath.Join(dst, "Documents/deep/gone.txt.sinty-part"), []byte("torn"), 0o600)
	os.WriteFile(filepath.Join(dst, "run.sh"), []byte("#!/bin/sh\n"), 0o755)
	st, _ := os.Stat(filepath.Join(src, "run.sh"))
	os.Chtimes(filepath.Join(dst, "run.sh"), st.ModTime(), st.ModTime())
	kept := inode(t, filepath.Join(dst, "run.sh"))
	if err := Copy(src, dst, "to-key", me(), nil); err != nil {
		t.Fatal(err)
	}
	if inode(t, filepath.Join(dst, "run.sh")) != kept {
		t.Fatal("a finished file was copied again")
	}
	for _, p := range []string{"Documents/big.bin.sinty-part", "Documents/deep/gone.txt.sinty-part"} {
		if _, err := os.Stat(filepath.Join(dst, p)); !os.IsNotExist(err) {
			t.Fatalf("torn part %s left behind", p)
		}
	}
	if err := Verify(src, dst, "to-key", nil); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFindsDamage(t *testing.T) {
	src, dst := home(t), t.TempDir()
	if err := Copy(src, dst, "from-key", me(), nil); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dst, "Documents/big.bin")
	st, _ := os.Stat(p)
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	f.WriteAt([]byte{0xff}, 1<<20)
	f.Close()
	os.Chtimes(p, st.ModTime(), st.ModTime())
	if err := Verify(src, dst, "from-key", nil); !errors.Is(err, ErrChanged) {
		t.Fatalf("damage not found: %v", err)
	}
	if err := RemoveSource(src, dst, "from-key"); err == nil {
		t.Fatal("source removed without a verified copy")
	}
	if _, err := os.Stat(filepath.Join(src, "run.sh")); err != nil {
		t.Fatal("source touched")
	}
}

func TestRemoveSourceRechecks(t *testing.T) {
	src, dst := home(t), t.TempDir()
	if err := Copy(src, dst, "to-key", me(), nil); err != nil {
		t.Fatal(err)
	}
	if err := Verify(src, dst, "to-key", nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(src, "late.txt"), []byte("written after the check"), 0o600)
	if err := RemoveSource(src, dst, "to-key"); !errors.Is(err, ErrChanged) {
		t.Fatalf("a file added after the check would be lost: %v", err)
	}
	os.Remove(filepath.Join(src, "late.txt"))
	if err := RemoveSource(src, dst, "to-key"); err != nil {
		t.Fatal(err)
	}
	left, _ := os.ReadDir(src)
	if len(left) != 0 {
		t.Fatalf("source not emptied: %v", left)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "Documents/deep/note.txt")); err != nil || string(b) != "hello" {
		t.Fatal("copy lost")
	}
	if _, err := os.Stat(filepath.Join(dst, Journal)); !os.IsNotExist(err) {
		t.Fatal("journal left behind")
	}
}

func TestCopyStaysInside(t *testing.T) {
	src, dst, outside := t.TempDir(), t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(src, "sub"), 0o700)
	os.WriteFile(filepath.Join(src, "sub/file"), []byte("x"), 0o600)
	os.Symlink(outside, filepath.Join(dst, "sub"))
	if err := Copy(src, dst, "to-key", me(), nil); err == nil {
		t.Fatal("copy went through a link out of the destination")
	}
	if left, _ := os.ReadDir(outside); len(left) != 0 {
		t.Fatalf("wrote outside: %v", left)
	}
}
