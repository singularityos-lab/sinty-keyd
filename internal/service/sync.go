package service

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	SyncNone     = ""
	SyncKey      = "key"
	SyncComputer = "computer"
)

var (
	errNotStartup = errors.New("this drive is not a startup Sinty Key")
	errNoSync     = errors.New("the Key and this computer have nothing to give each other")
)

type startupDrive struct {
	data, esp string
}

type startupState struct {
	direction  string
	keyVersion string
	pcVersion  string
}

func runUpdated(onLine func(string), args ...string) error {
	if onLine == nil {
		onLine = func(string) {}
	}
	return runReporting(append([]string{"/usr/libexec/updated.real"}, args...), onLine)
}

func (s *Service) startupDrive(device string) (startupDrive, error) {
	disk := filepath.Base(device)
	if strings.ContainsAny(disk, "/.") || disk == "" || !s.removable(disk) {
		return startupDrive{}, errNotStartup
	}
	var d startupDrive
	for _, p := range s.partitions(disk) {
		if s.partLabel(p) == "atom-data" {
			d.data = p
		}
	}
	d.esp = partName(disk, 1)
	if d.data == "" || d.data == d.esp {
		return startupDrive{}, errNotStartup
	}
	return d, nil
}

func (s *Service) mountStartup(d startupDrive, readOnly bool) (string, string, func(), error) {
	base := filepath.Join(s.cfg.PeekDir, "startup")
	data, esp := filepath.Join(base, "data"), filepath.Join(base, "esp")
	for _, dir := range []string{data, esp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", "", nil, err
		}
	}
	dev := func(p string) string { return filepath.Join(s.cfg.SysRoot, "dev", p) }
	if err := s.cfg.Mounter.Mount(dev(d.data), data, "", readOnly); err != nil {
		return "", "", nil, err
	}
	if err := s.cfg.Mounter.Mount(dev(d.esp), esp, "", readOnly); err != nil {
		s.cfg.Mounter.Unmount(data)
		return "", "", nil, err
	}
	return data, esp, func() {
		s.cfg.Mounter.Unmount(esp)
		s.cfg.Mounter.Unmount(data)
	}, nil
}

func walVersion(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var d struct {
		RootFS struct {
			Current string `json:"current"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return "", err
	}
	if d.RootFS.Current == "" || strings.ContainsAny(d.RootFS.Current, "/\\") {
		return "", fmt.Errorf("%s: no installed version", path)
	}
	return d.RootFS.Current, nil
}

func versionNum(v string) (int, bool) {
	i := len(v)
	for i > 0 && v[i-1] >= '0' && v[i-1] <= '9' {
		i--
	}
	if i == len(v) {
		return 0, false
	}
	n, err := strconv.Atoi(v[i:])
	return n, err == nil
}

func hasAnchor(rootfs, version string) bool {
	for _, f := range []string{"manifest.json", "manifest.json.sig", "signing-cert.json", "signing-cert.json.sig"} {
		if _, err := os.Stat(filepath.Join(rootfs, "release", version, f)); err != nil {
			return false
		}
	}
	return true
}

func peArch(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var hdr [64]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil || hdr[0] != 'M' || hdr[1] != 'Z' {
		return ""
	}
	off := int64(binary.LittleEndian.Uint32(hdr[0x3c:]))
	var pe [6]byte
	if _, err := f.ReadAt(pe[:], off); err != nil || string(pe[:4]) != "PE\x00\x00" {
		return ""
	}
	switch binary.LittleEndian.Uint16(pe[4:]) {
	case 0x8664:
		return "x86_64"
	case 0xaa64:
		return "aarch64"
	}
	return ""
}

func releaseArch(rootfs, esp, version string) string {
	if b, err := os.ReadFile(filepath.Join(rootfs, "release", version, "manifest.json")); err == nil {
		var m struct {
			Arch string `json:"arch"`
		}
		if json.Unmarshal(b, &m) == nil {
			if m.Arch == "" {
				return "x86_64"
			}
			return m.Arch
		}
	}
	return peArch(filepath.Join(esp, "EFI/atom/kernelcache-active.efi"))
}

func (s *Service) localRootfs() string {
	return filepath.Join(s.cfg.SysRoot, "boot/rootfs")
}

func (s *Service) syncState(data, esp string) (startupState, error) {
	keyRootfs := filepath.Join(data, "boot/rootfs")
	kv, err := walVersion(filepath.Join(keyRootfs, "deployment.json"))
	if err != nil {
		return startupState{}, err
	}
	pv, err := walVersion(filepath.Join(s.localRootfs(), "deployment.json"))
	if err != nil {
		return startupState{}, err
	}
	st := startupState{keyVersion: kv, pcVersion: pv}
	if releaseArch(keyRootfs, esp, kv) != localArch() {
		return st, nil
	}
	k, ok1 := versionNum(kv)
	p, ok2 := versionNum(pv)
	if !ok1 || !ok2 {
		return st, nil
	}
	switch {
	case k < p && hasAnchor(s.localRootfs(), pv):
		st.direction = SyncKey
	case k > p && hasAnchor(keyRootfs, kv):
		st.direction = SyncComputer
	}
	return st, nil
}

func (s *Service) StartupSync(sender dbus.Sender, device string) (string, string, string, *dbus.Error) {
	if _, derr := s.caller(sender); derr != nil {
		return "", "", "", derr
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	d, err := s.startupDrive(device)
	if err != nil {
		return "", "", "", fail(err)
	}
	data, esp, done, err := s.mountStartup(d, true)
	if err != nil {
		return "", "", "", fail(err)
	}
	defer done()
	st, err := s.syncState(data, esp)
	if err != nil {
		return "", "", "", fail(err)
	}
	return st.direction, st.keyVersion, st.pcVersion, nil
}

func (s *Service) exportDir() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	dir := filepath.Join(s.cfg.CacheDir, "export-"+hex.EncodeToString(raw))
	return dir, os.MkdirAll(s.cfg.CacheDir, 0o700)
}

func (s *Service) syncProgress(device string, from, span uint32) func(string) {
	return func(line string) {
		v, ok := strings.CutPrefix(line, "progress ")
		if !ok {
			return
		}
		pct, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
		if err == nil && pct <= 100 {
			s.progress(device, from+span*uint32(pct)/100)
		}
	}
}

func (s *Service) UpdateStartupKey(sender dbus.Sender, device string) *dbus.Error {
	if _, derr := s.caller(sender); derr != nil {
		return derr
	}
	return s.syncStartup(device, SyncKey)
}

func (s *Service) UpdateFromStartupKey(sender dbus.Sender, device string) *dbus.Error {
	if !s.admin(sender) {
		return dbus.NewError(errorPfx+"NotAllowed", []interface{}{"only an administrator can update this computer"})
	}
	return s.syncStartup(device, SyncComputer)
}

func (s *Service) syncStartup(device, want string) *dbus.Error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	d, err := s.startupDrive(device)
	if err != nil {
		return fail(err)
	}
	data, esp, done, err := s.mountStartup(d, want == SyncComputer)
	if err != nil {
		return fail(err)
	}
	defer done()
	st, err := s.syncState(data, esp)
	if err != nil {
		return fail(err)
	}
	if st.direction != want {
		return fail(errNoSync)
	}
	out, err := s.exportDir()
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(out)
	keyRootfs := filepath.Join(data, "boot/rootfs")
	keyESP := filepath.Join(esp, "EFI/atom")
	s.progress(device, 0)
	if want == SyncKey {
		err = s.cfg.Updated(nil, "export-release", "--out", out)
		if err == nil {
			err = s.cfg.Updated(s.syncProgress(device, 0, 100), "stage-from", "--target", "--from", out,
				"--wal", filepath.Join(keyRootfs, "deployment.json"), "--rootfs-dir", keyRootfs, "--esp-dir", keyESP,
				"--stage-lock", filepath.Join(s.cfg.CacheDir, "startup-stage.lock"))
		}
	} else {
		err = s.cfg.Updated(nil, "export-release", "--out", out,
			"--wal", filepath.Join(keyRootfs, "deployment.json"), "--rootfs-dir", keyRootfs, "--esp-dir", keyESP)
		if err == nil {
			err = s.cfg.Updated(s.syncProgress(device, 0, 100), "stage-from", "--from", out)
		}
	}
	if err != nil {
		return fail(driveError(err))
	}
	s.progress(device, 100)
	return nil
}
