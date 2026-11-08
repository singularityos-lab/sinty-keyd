package backup

import (
	"archive/tar"
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/singularityos-lab/sinty-keyd/internal/seal"
)

const (
	magic     = "SINTYKEYBACKUP1\n"
	chunkSize = 64 << 10
	maxMeta   = 64 << 10
)

var (
	ErrNotBackup = errors.New("not a Sinty Key backup")
	ErrWrongCode = errors.New("wrong recovery code")
	ErrDamaged   = errors.New("the backup is damaged or was changed")
)

type Meta struct {
	ID       string    `json:"id"`
	Created  time.Time `json:"created"`
	Recovery []byte    `json:"recovery"`
	Salt     []byte    `json:"salt"`
}

func streamKey(master, salt []byte) []byte {
	k := make([]byte, chacha20poly1305.KeySize)
	io.ReadFull(hkdf.New(sha256.New, master, salt, []byte("sinty-key backup v1")), k)
	return k
}

type sealer struct {
	w     io.Writer
	aead  interface{ Seal(dst, nonce, plaintext, ad []byte) []byte }
	ad    []byte
	count uint64
	buf   []byte
}

func (s *sealer) emit(final bool) error {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], s.count)
	s.count++
	ad := append(append([]byte{}, s.ad...), 0)
	if final {
		ad[len(ad)-1] = 1
	}
	ct := s.aead.Seal(nil, nonce, s.buf, ad)
	s.buf = s.buf[:0]
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(ct)))
	if final {
		hdr[4] = 1
	}
	if _, err := s.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := s.w.Write(ct)
	return err
}

func (s *sealer) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		room := chunkSize - len(s.buf)
		take := min(room, len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		n += take
		if len(s.buf) == chunkSize {
			if err := s.emit(false); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func Write(w io.Writer, id string, recovery, master []byte, dir string, now time.Time) error {
	salt, err := seal.Random(32)
	if err != nil {
		return err
	}
	meta, err := json.Marshal(Meta{ID: id, Created: now.UTC().Truncate(time.Second), Recovery: recovery, Salt: salt})
	if err != nil {
		return err
	}
	k := streamKey(master, salt)
	defer seal.Wipe(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(meta)))
	bw.WriteString(magic)
	bw.Write(n[:])
	bw.Write(meta)
	sum := sha256.Sum256(meta)
	s := &sealer{w: bw, aead: aead, ad: sum[:], buf: make([]byte, 0, chunkSize)}
	tw := tar.NewWriter(s)
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		link := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		} else if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		h, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := s.emit(true); err != nil {
		return err
	}
	return bw.Flush()
}

func ReadMeta(r *bufio.Reader) (*Meta, []byte, error) {
	head := make([]byte, len(magic)+4)
	if _, err := io.ReadFull(r, head); err != nil || string(head[:len(magic)]) != magic {
		return nil, nil, ErrNotBackup
	}
	n := binary.BigEndian.Uint32(head[len(magic):])
	if n == 0 || n > maxMeta {
		return nil, nil, ErrNotBackup
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, nil, ErrNotBackup
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil || len(m.Salt) == 0 {
		return nil, nil, ErrNotBackup
	}
	return &m, raw, nil
}

type opener struct {
	r     *bufio.Reader
	aead  interface{ Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) }
	ad    []byte
	count uint64
	buf   []byte
	done  bool
}

func (o *opener) Read(p []byte) (int, error) {
	for len(o.buf) == 0 {
		if o.done {
			return 0, io.EOF
		}
		var hdr [5]byte
		if _, err := io.ReadFull(o.r, hdr[:]); err != nil {
			return 0, ErrDamaged
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		if n > chunkSize+chacha20poly1305.Overhead || hdr[4] > 1 {
			return 0, ErrDamaged
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(o.r, ct); err != nil {
			return 0, ErrDamaged
		}
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], o.count)
		o.count++
		ad := append(append([]byte{}, o.ad...), hdr[4])
		pt, err := o.aead.Open(nil, nonce, ct, ad)
		if err != nil {
			return 0, ErrDamaged
		}
		o.buf = pt
		o.done = hdr[4] == 1
	}
	n := copy(p, o.buf)
	o.buf = o.buf[n:]
	return n, nil
}

func Open(r io.Reader, code string) (*Meta, []byte, io.Reader, error) {
	br := bufio.NewReader(r)
	m, raw, err := ReadMeta(br)
	if err != nil {
		return nil, nil, nil, err
	}
	master, err := seal.Unwrap(m.Recovery, []byte(seal.NormalizeCode(code)))
	if errors.Is(err, seal.ErrWrongSecret) {
		return nil, nil, nil, ErrWrongCode
	}
	if err != nil {
		return nil, nil, nil, err
	}
	k := streamKey(master, m.Salt)
	defer seal.Wipe(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		seal.Wipe(master)
		return nil, nil, nil, err
	}
	sum := sha256.Sum256(raw)
	return m, master, &opener{r: br, aead: aead, ad: sum[:]}, nil
}

func Extract(src io.Reader, dir string) error {
	tr := tar.NewReader(src)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, ErrDamaged) {
				return ErrDamaged
			}
			return err
		}
		name := filepath.FromSlash(h.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("%w: unsafe path %q", ErrDamaged, h.Name)
		}
		dst := filepath.Join(dir, name)
		mode := fs.FileMode(h.Mode).Perm()
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				if errors.Is(err, ErrDamaged) {
					return ErrDamaged
				}
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			os.Chtimes(dst, h.ModTime, h.ModTime)
		case tar.TypeSymlink:
			if strings.HasPrefix(h.Linkname, "/") || !filepath.IsLocal(filepath.Join(filepath.Dir(name), filepath.FromSlash(h.Linkname))) {
				return fmt.Errorf("%w: link out of the backup %q", ErrDamaged, h.Name)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			if err := os.Symlink(h.Linkname, dst); err != nil {
				return err
			}
		}
	}
	if _, err := io.Copy(io.Discard, src); err != nil {
		return ErrDamaged
	}
	return nil
}
