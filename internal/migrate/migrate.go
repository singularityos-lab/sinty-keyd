package migrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
)

const (
	Journal = ".sinty-move"
	partExt = ".sinty-part"

	Copying  = "copying"
	Verified = "verified"
)

var ErrChanged = errors.New("the copy does not match the original")

type Progress func(done, total int64)

type journal struct {
	Source string `json:"source"`
	Phase  string `json:"phase"`
}

type Owner struct {
	UID, GID int
}

func skip(p string) bool {
	return p == Journal || p == ".cache" || strings.HasSuffix(p, partExt)
}

func walk(root *os.Root, fn func(p string, d fs.DirEntry) error) error {
	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		if skip(p) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		return fn(p, d)
	})
}

func Size(src string) (int64, error) {
	root, err := os.OpenRoot(src)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	var total int64
	err = walk(root, func(p string, d fs.DirEntry) error {
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func State(dst, source string) string {
	b, err := os.ReadFile(path.Join(dst, Journal))
	if err != nil {
		return ""
	}
	var j journal
	if json.Unmarshal(b, &j) != nil || j.Source != source {
		return ""
	}
	return j.Phase
}

func mark(dst *os.Root, source, phase string) error {
	b, _ := json.Marshal(journal{Source: source, Phase: phase})
	f, err := dst.OpenFile(Journal+partExt, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return dst.Rename(Journal+partExt, Journal)
}

func Copy(src, dst, source string, owner Owner, progress Progress) error {
	if progress == nil {
		progress = func(int64, int64) {}
	}
	total, err := Size(src)
	if err != nil {
		return err
	}
	from, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer to.Close()
	if err := mark(to, source, Copying); err != nil {
		return err
	}
	var done int64
	progress(0, total)
	err = walk(from, func(p string, d fs.DirEntry) error {
		info, err := from.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := to.MkdirAll(p, 0o700); err != nil {
				return err
			}
			if err := to.Lchown(p, owner.UID, owner.GID); err != nil {
				return err
			}
			return to.Chmod(p, info.Mode().Perm())
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := from.Readlink(p)
			if err != nil {
				return err
			}
			if have, err := to.Readlink(p); err == nil && have == target {
				return nil
			}
			if err := to.RemoveAll(p); err != nil {
				return err
			}
			if err := to.Symlink(target, p); err != nil {
				return err
			}
			return to.Lchown(p, owner.UID, owner.GID)
		case info.Mode().IsRegular():
			if have, err := to.Lstat(p); err == nil && have.Mode().IsRegular() && have.Size() == info.Size() && have.ModTime().Equal(info.ModTime()) {
				done += info.Size()
				progress(done, total)
				return nil
			}
			if err := copyFile(from, to, p, info, owner, func(n int64) {
				progress(done+n, total)
			}); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			done += info.Size()
			progress(done, total)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sweep(to)
}

func copyFile(from, to *os.Root, p string, info fs.FileInfo, owner Owner, step func(int64)) error {
	in, err := from.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	part := p + partExt
	out, err := to.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	var n int64
	for {
		r, rerr := in.Read(buf)
		if r > 0 {
			if _, err := out.Write(buf[:r]); err != nil {
				out.Close()
				return err
			}
			n += int64(r)
			step(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			return rerr
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := to.Lchown(part, owner.UID, owner.GID); err != nil {
		return err
	}
	if err := to.Chmod(part, info.Mode().Perm()); err != nil {
		return err
	}
	if err := to.Chtimes(part, info.ModTime(), info.ModTime()); err != nil {
		return err
	}
	return to.Rename(part, p)
}

func sweep(to *os.Root) error {
	var parts []string
	fs.WalkDir(to.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, partExt) && p != Journal+partExt {
			parts = append(parts, p)
		}
		return nil
	})
	for _, p := range parts {
		if err := to.Remove(p); err != nil {
			return err
		}
	}
	return nil
}

func digest(root *os.Root, p string) ([]byte, error) {
	f, err := root.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func Verify(src, dst, source string, progress Progress) error {
	if progress == nil {
		progress = func(int64, int64) {}
	}
	total, err := Size(src)
	if err != nil {
		return err
	}
	from, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer to.Close()
	var done int64
	progress(0, total)
	err = walk(from, func(p string, d fs.DirEntry) error {
		info, err := from.Lstat(p)
		if err != nil {
			return err
		}
		have, err := to.Lstat(p)
		if err != nil {
			return fmt.Errorf("%w: %s is missing", ErrChanged, p)
		}
		switch {
		case info.IsDir():
			if !have.IsDir() {
				return fmt.Errorf("%w: %s", ErrChanged, p)
			}
		case info.Mode()&fs.ModeSymlink != 0:
			a, err1 := from.Readlink(p)
			b, err2 := to.Readlink(p)
			if err1 != nil || err2 != nil || a != b {
				return fmt.Errorf("%w: %s", ErrChanged, p)
			}
		case info.Mode().IsRegular():
			if !have.Mode().IsRegular() || have.Size() != info.Size() {
				return fmt.Errorf("%w: %s", ErrChanged, p)
			}
			a, err := digest(from, p)
			if err != nil {
				return err
			}
			b, err := digest(to, p)
			if err != nil {
				return err
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("%w: %s", ErrChanged, p)
			}
			done += info.Size()
			progress(done, total)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return mark(to, source, Verified)
}

func RemoveSource(src, dst, source string) error {
	if State(dst, source) != Verified {
		return errors.New("the copy was not verified")
	}
	if err := Verify(src, dst, source, nil); err != nil {
		return err
	}
	from, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer from.Close()
	entries, err := fs.ReadDir(from.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == Journal {
			continue
		}
		if err := from.RemoveAll(e.Name()); err != nil {
			return err
		}
	}
	return Finish(dst)
}

func Finish(dst string) error {
	err := os.Remove(path.Join(dst, Journal))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
