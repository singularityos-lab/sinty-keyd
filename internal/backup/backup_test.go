package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-keyd/internal/seal"
)

func fixture(t *testing.T) (string, []byte, []byte, string) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "Photos", "2026"), 0o755)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o600)
	big := bytes.Repeat([]byte("0123456789abcdef"), 20000)
	os.WriteFile(filepath.Join(dir, "Photos", "2026", "big.raw"), big, 0o644)
	os.Symlink("notes.txt", filepath.Join(dir, "latest"))
	master, _ := seal.Random(seal.KeySize)
	code, _ := seal.RecoveryCode()
	rec, err := seal.Wrap(master, []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	return dir, master, rec, code
}

func TestRoundTrip(t *testing.T) {
	dir, master, rec, code := fixture(t)
	var buf bytes.Buffer
	if err := Write(&buf, "abc", rec, master, dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("hello")) || bytes.Contains(buf.Bytes(), []byte("0123456789abcdef0123")) {
		t.Fatal("plaintext in the backup")
	}
	m, got, src, err := Open(bytes.NewReader(buf.Bytes()), code)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "abc" || !bytes.Equal(got, master) {
		t.Fatal("wrong meta or master")
	}
	out := t.TempDir()
	if err := Extract(src, out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"notes.txt", "Photos/2026/big.raw"} {
		a, _ := os.ReadFile(filepath.Join(dir, f))
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil || !bytes.Equal(a, b) {
			t.Fatalf("%s differs", f)
		}
	}
	if l, _ := os.Readlink(filepath.Join(out, "latest")); l != "notes.txt" {
		t.Fatalf("link %q", l)
	}
}

func TestWrongCode(t *testing.T) {
	dir, master, rec, _ := fixture(t)
	var buf bytes.Buffer
	Write(&buf, "abc", rec, master, dir, time.Now())
	if _, _, _, err := Open(bytes.NewReader(buf.Bytes()), "AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("got %v", err)
	}
}

func TestDamage(t *testing.T) {
	dir, master, rec, code := fixture(t)
	var buf bytes.Buffer
	Write(&buf, "abc", rec, master, dir, time.Now())
	data := buf.Bytes()
	cases := map[string][]byte{
		"flipped":   append(append([]byte{}, data[:len(data)/2]...), append([]byte{data[len(data)/2] ^ 1}, data[len(data)/2+1:]...)...),
		"truncated": data[:len(data)-200],
	}
	for name, d := range cases {
		_, _, src, err := Open(bytes.NewReader(d), code)
		if err != nil {
			t.Fatalf("%s: open %v", name, err)
		}
		if err := Extract(src, t.TempDir()); !errors.Is(err, ErrDamaged) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	if _, _, _, err := Open(bytes.NewReader([]byte("nope")), code); !errors.Is(err, ErrNotBackup) {
		t.Fatalf("got %v", err)
	}
}
