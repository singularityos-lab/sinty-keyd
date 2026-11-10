package badge

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	User  = "sinty-badge"
	UID   = 61000
	Home  = "/run/sinty-badge/home"
	Shell = "/bin/bash"
)

var (
	ErrUnverified = errors.New("this computer does not run a verified system")
	ErrTaken      = errors.New("the badge account name is already used on this computer")
)

func Allowed(policy string) bool {
	data, err := os.ReadFile(policy)
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) != "off"
}

func SetAllowed(policy string, on bool) error {
	if on {
		if err := os.Remove(policy); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(policy), 0o755); err != nil {
		return err
	}
	return writeAtomic(policy, []byte("off\n"), 0o644)
}

func Verified(sysroot string) error {
	cmdline, err := os.ReadFile(filepath.Join(sysroot, "proc/cmdline"))
	if err != nil {
		return ErrUnverified
	}
	hash := ""
	for _, f := range strings.Fields(string(cmdline)) {
		if v, ok := strings.CutPrefix(f, "sing.roothash="); ok {
			hash = v
		}
	}
	if len(hash) < 64 {
		return fmt.Errorf("%w: no root hash on the kernel command line", ErrUnverified)
	}
	lockdown, _ := os.ReadFile(filepath.Join(sysroot, "sys/kernel/security/lockdown"))
	if !strings.Contains(string(lockdown), "[integrity]") && !strings.Contains(string(lockdown), "[confidentiality]") {
		return fmt.Errorf("%w: kernel lockdown is off", ErrUnverified)
	}
	uuids, _ := filepath.Glob(filepath.Join(sysroot, "sys/block/dm-*/dm/uuid"))
	for _, u := range uuids {
		if data, err := os.ReadFile(u); err == nil && strings.HasPrefix(string(data), "CRYPT-VERITY-") {
			return nil
		}
	}
	return fmt.Errorf("%w: the system is not on a verity device", ErrUnverified)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".sinty-badge"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if st, err := os.Stat(path); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			f.Chown(int(sys.Uid), int(sys.Gid))
		}
		f.Chmod(st.Mode().Perm())
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func lock(etc string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(etc, ".pwd.lock"), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

type table struct {
	name  string
	mode  os.FileMode
	entry func(gecos string) string
}

func tables() []table {
	id := strconv.Itoa(UID)
	return []table{
		{"passwd", 0o644, func(gecos string) string {
			return strings.Join([]string{User, "x", id, id, gecos, Home, Shell}, ":")
		}},
		{"group", 0o644, func(string) string { return User + ":x:" + id + ":" }},
		{"shadow", 0o600, func(string) string { return User + ":*:1::::::" }},
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func cleanGecos(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ':' || r == '\n' || r == ',' || r < 0x20 {
			return -1
		}
		return r
	}, s)
}

func AddAccount(etc, owner string) error {
	unlock, err := lock(etc)
	if err != nil {
		return err
	}
	defer unlock()
	id := strconv.Itoa(UID)
	for _, t := range tables() {
		lines, err := readLines(filepath.Join(etc, t.name))
		if err != nil {
			return err
		}
		for _, l := range lines {
			f := strings.SplitN(l, ":", 4)
			if f[0] == User {
				continue
			}
			if t.name != "shadow" && len(f) > 2 && f[2] == id {
				return ErrTaken
			}
		}
	}
	for _, t := range tables() {
		path := filepath.Join(etc, t.name)
		lines, err := readLines(path)
		if err != nil {
			return err
		}
		kept := lines[:0]
		for _, l := range lines {
			if !strings.HasPrefix(l, User+":") {
				kept = append(kept, l)
			}
		}
		kept = append(kept, t.entry(cleanGecos(owner)))
		if err := writeAtomic(path, []byte(strings.Join(kept, "\n")+"\n"), t.mode); err != nil {
			return err
		}
	}
	return nil
}

func RemoveAccount(etc string) error {
	unlock, err := lock(etc)
	if err != nil {
		return err
	}
	defer unlock()
	for _, t := range tables() {
		path := filepath.Join(etc, t.name)
		lines, err := readLines(path)
		if err != nil {
			return err
		}
		kept := lines[:0]
		changed := false
		for _, l := range lines {
			if strings.HasPrefix(l, User+":") {
				changed = true
				continue
			}
			kept = append(kept, l)
		}
		if !changed {
			continue
		}
		body := strings.Join(kept, "\n")
		if len(kept) > 0 {
			body += "\n"
		}
		if err := writeAtomic(path, []byte(body), t.mode); err != nil {
			return err
		}
	}
	return nil
}

func NewTicket(path string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	t := hex.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := writeAtomic(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

func Processes(proc string, uid int) []int {
	entries, _ := os.ReadDir(proc)
	var out []int
	want := strconv.Itoa(uid)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(proc, e.Name(), "status"))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "Uid:" {
				if f[1] == want {
					out = append(out, pid)
				}
				break
			}
		}
	}
	return out
}
