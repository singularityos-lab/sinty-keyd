package tpm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrWrongPIN    = errors.New("wrong PIN")
	ErrUnavailable = errors.New("no TPM")
)

type TPM interface {
	Fingerprint() (string, error)
	Seal(key []byte, pin string) (pub, priv []byte, err error)
	Unseal(pin string, pub, priv []byte) ([]byte, error)
	NewCounter() (uint32, error)
	Counter(index uint32) (uint64, error)
	Bump(index uint32) (uint64, error)
}

type Helper struct {
	Path    string
	WorkDir string
}

func NewHelper(workDir string) *Helper {
	return &Helper{Path: "/usr/libexec/sintykey-tpm", WorkDir: workDir}
}

func (h *Helper) run(args ...string) (string, int, error) {
	if _, err := os.Stat(h.Path); err != nil {
		return "", 0, ErrUnavailable
	}
	cmd := exec.Command(h.Path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return strings.TrimSpace(string(out)), ee.ExitCode(), nil
	}
	if err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(string(out)), 0, nil
}

func (h *Helper) scratch() (string, func(), error) {
	if err := os.MkdirAll(h.WorkDir, 0o700); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(h.WorkDir, "op-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { wipeDir(dir) }, nil
}

func wipeDir(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if fi, err := os.Stat(p); err == nil {
			os.WriteFile(p, make([]byte, fi.Size()), 0o600)
		}
	}
	os.RemoveAll(dir)
}

func (h *Helper) Fingerprint() (string, error) {
	out, code, err := h.run("ek-fingerprint")
	if err != nil {
		return "", err
	}
	if code != 0 || out == "" {
		return "", fmt.Errorf("ek-fingerprint failed (%d)", code)
	}
	return out, nil
}

func (h *Helper) Seal(key []byte, pin string) ([]byte, []byte, error) {
	dir, done, err := h.scratch()
	if err != nil {
		return nil, nil, err
	}
	defer done()
	kf, pf := filepath.Join(dir, "key"), filepath.Join(dir, "pin")
	pub, priv := filepath.Join(dir, "pub"), filepath.Join(dir, "priv")
	if err := os.WriteFile(kf, key, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(pf, []byte(pin), 0o600); err != nil {
		return nil, nil, err
	}
	if _, code, err := h.run("seal", kf, pf, pub, priv); err != nil || code != 0 {
		if err == nil {
			err = fmt.Errorf("seal failed (%d)", code)
		}
		return nil, nil, err
	}
	a, err := os.ReadFile(pub)
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(priv)
	return a, b, err
}

func (h *Helper) Unseal(pin string, pub, priv []byte) ([]byte, error) {
	dir, done, err := h.scratch()
	if err != nil {
		return nil, err
	}
	defer done()
	pf, pubf, privf, out := filepath.Join(dir, "pin"), filepath.Join(dir, "pub"), filepath.Join(dir, "priv"), filepath.Join(dir, "out")
	for name, data := range map[string][]byte{pf: []byte(pin), pubf: pub, privf: priv} {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			return nil, err
		}
	}
	_, code, err := h.run("unseal", pf, pubf, privf, out)
	if err != nil {
		return nil, err
	}
	switch code {
	case 0:
		return os.ReadFile(out)
	case 1:
		return nil, ErrWrongPIN
	}
	return nil, fmt.Errorf("unseal failed (%d)", code)
}

func (h *Helper) NewCounter() (uint32, error) {
	out, code, err := h.run("counter-define")
	if err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, fmt.Errorf("counter-define failed (%d)", code)
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(out, "0x"), 16, 32)
	return uint32(v), err
}

func (h *Helper) counter(cmd string, index uint32) (uint64, error) {
	out, code, err := h.run(cmd, fmt.Sprintf("0x%08x", index))
	if err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, fmt.Errorf("%s failed (%d)", cmd, code)
	}
	return strconv.ParseUint(out, 10, 64)
}

func (h *Helper) Counter(index uint32) (uint64, error) {
	return h.counter("counter-read", index)
}

func (h *Helper) Bump(index uint32) (uint64, error) {
	return h.counter("counter-bump", index)
}
