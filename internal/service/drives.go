package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/key"
)

const keyLabel = "SINTYKEY"

type DriveInfo struct {
	Device string
	Name   string
	Size   uint64
	Root   string
	Key    bool
}

var errSystemDrive = errors.New("this drive holds the running system")

func (s *Service) caller(sender dbus.Sender) (*user.User, *dbus.Error) {
	uid, err := s.senderUID(sender)
	if err != nil {
		return nil, fail(err)
	}
	if uid != 0 && uid < 1000 {
		return nil, dbus.NewError(errorPfx+"NotAllowed", []interface{}{"not allowed"})
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, fail(err)
	}
	return u, nil
}

func (s *Service) blockDir(name string) string {
	return filepath.Join(s.cfg.SysRoot, "sys/class/block", name)
}

func (s *Service) partitions(disk string) []string {
	out := []string{}
	entries, err := os.ReadDir(s.blockDir(disk))
	if err != nil {
		return out
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), disk) {
			if _, err := os.Stat(filepath.Join(s.blockDir(disk), e.Name(), "partition")); err == nil {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

func (s *Service) mountOf(name string, mounted map[string]string) string {
	num, err := os.ReadFile(filepath.Join(s.blockDir(name), "dev"))
	if err != nil {
		return ""
	}
	return mounted[strings.TrimSpace(string(num))]
}

func userMount(p string) bool {
	return p == "" || strings.HasPrefix(p, "/run/media/") || strings.HasPrefix(p, "/media/") || p == "/run/sintylogs"
}

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func (s *Service) driveName(disk string) string {
	dev := filepath.Join(s.blockDir(disk), "device")
	name := strings.TrimSpace(readTrim(filepath.Join(dev, "vendor")) + " " + readTrim(filepath.Join(dev, "model")))
	if name == "" {
		return "USB Drive"
	}
	return name
}

func (s *Service) Drives(sender dbus.Sender) ([]DriveInfo, *dbus.Error) {
	if _, derr := s.caller(sender); derr != nil {
		return nil, derr
	}
	out, err := s.drives()
	if err != nil {
		return nil, fail(err)
	}
	return out, nil
}

func (s *Service) drives() ([]DriveInfo, error) {
	entries, err := os.ReadDir(filepath.Join(s.cfg.SysRoot, "sys/class/block"))
	if err != nil {
		return nil, err
	}
	mounted, _ := s.devNumbers()
	out := []DriveInfo{}
	for _, e := range entries {
		disk := e.Name()
		if strings.HasPrefix(disk, "loop") || strings.HasPrefix(disk, "ram") || strings.HasPrefix(disk, "zram") || strings.HasPrefix(disk, "dm-") {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.blockDir(disk), "partition")); err == nil {
			continue
		}
		if !s.removable(disk) {
			continue
		}
		sectors, _ := strconv.ParseUint(readTrim(filepath.Join(s.blockDir(disk), "size")), 10, 64)
		if sectors == 0 {
			continue
		}
		d := DriveInfo{Device: "/dev/" + disk, Name: s.driveName(disk), Size: sectors * 512}
		system := false
		for _, part := range append([]string{disk}, s.partitions(disk)...) {
			root := s.mountOf(part, mounted)
			if !userMount(root) && !strings.HasPrefix(root, s.cfg.PeekDir+"/") {
				system = true
			}
			if root != "" && d.Root == "" && strings.HasPrefix(root, "/run/media/") {
				if _, err := key.Open(root); err == nil {
					d.Root, d.Key = root, true
				}
			}
		}
		if system {
			continue
		}
		for _, p := range s.Present() {
			if p.Device == d.Device || strings.HasPrefix(p.Device, d.Device) {
				d.Key = true
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *Service) eraseTarget(sender dbus.Sender, device string) (string, *user.User, *dbus.Error) {
	u, derr := s.caller(sender)
	if derr != nil {
		return "", nil, derr
	}
	list, derr := s.Drives(sender)
	if derr != nil {
		return "", nil, derr
	}
	for _, d := range list {
		if d.Device == device {
			disk := filepath.Base(device)
			mounted, _ := s.devNumbers()
			for _, part := range append(s.partitions(disk), disk) {
				if root := s.mountOf(part, mounted); root != "" {
					s.mu.Lock()
					delete(s.open, root)
					s.mu.Unlock()
					if err := syscall.Unmount(root, syscall.MNT_DETACH); err != nil {
						return "", nil, fail(fmt.Errorf("%s: %w", root, err))
					}
				}
			}
			return device, u, nil
		}
	}
	return "", nil, fail(errSystemDrive)
}

func tool(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", name, strings.TrimSpace(string(out)))
	}
	return nil
}

func partName(disk string, n int) string {
	last := disk[len(disk)-1]
	if last >= '0' && last <= '9' {
		return fmt.Sprintf("%sp%d", disk, n)
	}
	return fmt.Sprintf("%s%d", disk, n)
}

func (s *Service) mountFor(u *user.User, dev, label string) (string, error) {
	base := filepath.Join(s.cfg.SysRoot, "run/media", u.Username)
	if err := os.MkdirAll(base, 0o750); err != nil {
		return "", err
	}
	gid, _ := strconv.Atoi(u.Gid)
	uid, _ := strconv.Atoi(u.Uid)
	_ = os.Chown(base, 0, gid)
	root := filepath.Join(base, label)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	opts := fmt.Sprintf("uid=%d,gid=%d,fmask=0077,dmask=0077", uid, gid)
	if err := s.cfg.Mounter.Mount(dev, root, opts, false); err != nil {
		os.Remove(root)
		return "", err
	}
	_ = os.Chown(root, uid, gid)
	return root, nil
}

func (s *Service) Prepare(sender dbus.Sender, device string) (string, *dbus.Error) {
	dev, u, derr := s.eraseTarget(sender, device)
	if derr != nil {
		return "", derr
	}
	part := partName(dev, 1)
	if err := tool("wipefs", "-a", dev); err != nil {
		return "", fail(err)
	}
	sf := exec.Command("sfdisk", "--quiet", dev)
	sf.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	sf.Stdin = strings.NewReader("label: gpt\n,,L\n")
	if out, err := sf.CombinedOutput(); err != nil {
		return "", fail(fmt.Errorf("sfdisk: %s", strings.TrimSpace(string(out))))
	}
	_ = tool("partprobe", dev)
	_ = tool("udevadm", "settle")
	if err := tool("mkfs.ext4", "-F", "-q", "-O", "encrypt", "-L", keyLabel, part); err != nil {
		return "", fail(err)
	}
	root, err := s.mountFor(u, part, "Sinty Key")
	if err != nil {
		return "", fail(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	_ = os.Chown(root, uid, gid)
	_ = os.Chmod(root, 0o700)
	s.Scan()
	return root, nil
}

func (s *Service) MakeBootable(sender dbus.Sender, device string) *dbus.Error {
	dev, _, derr := s.eraseTarget(sender, device)
	if derr != nil {
		return derr
	}
	if err := tool("wipefs", "-a", dev); err != nil {
		return fail(err)
	}
	if err := tool("atom-install", "--key", dev); err != nil {
		return fail(err)
	}
	s.Scan()
	return nil
}

func (s *Service) Open(sender dbus.Sender, device, pin string) (string, string, *dbus.Error) {
	u, derr := s.caller(sender)
	if derr != nil {
		return "", "", derr
	}
	var dev *PresentKey
	for _, p := range s.Present() {
		if p.Device == device {
			dev = &p
			break
		}
	}
	if dev == nil {
		return "", "", fail(errUnknownDevice)
	}
	mounted, _ := s.devNumbers()
	root := s.mountOf(filepath.Base(device), mounted)
	if root == "" {
		var err error
		root, err = s.mountFor(u, filepath.Join(s.cfg.SysRoot, "dev", filepath.Base(device)), "Sinty Key "+dev.ID[:min(6, len(dev.ID))])
		if err != nil {
			return "", "", fail(err)
		}
	}
	mode, derr := s.Unlock(root, pin)
	s.Scan()
	if derr != nil {
		return root, "", derr
	}
	return root, mode, nil
}
