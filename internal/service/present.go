package service

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/key"
	"github.com/singularityos-lab/sinty-keyd/internal/keyfile"
)

const (
	StateLocked = "locked"
	StateCopy   = "copy"
)

var fsTypes = []string{"ext4", "f2fs", "btrfs", "exfat", "vfat", "xfs"}

type PresentKey struct {
	Device string
	ID     string
	Owner  string
	State  string
}

type Mounter interface {
	Mount(dev, dir, opts string, readOnly bool) error
	Unmount(dir string) error
}

type sysMounter struct{}

func (sysMounter) Mount(dev, dir, opts string, readOnly bool) error {
	flags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
	if readOnly {
		flags |= syscall.MS_RDONLY
	}
	var last error
	for _, fs := range fsTypes {
		o := opts
		if fs != "vfat" && fs != "exfat" {
			o = ""
		}
		if last = syscall.Mount(dev, dir, fs, flags, o); last == nil {
			return nil
		}
	}
	return last
}

func (sysMounter) Unmount(dir string) error { return syscall.Unmount(dir, syscall.MNT_DETACH) }

func ownerOf(root string) string {
	rest, ok := strings.CutPrefix(filepath.Clean(root), "/run/media/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "/")
	return name
}

func (s *Service) removable(name string) bool {
	sys := filepath.Join(s.cfg.SysRoot, "sys/class/block", name)
	disk := sys
	if _, err := os.Stat(filepath.Join(sys, "partition")); err == nil {
		disk = filepath.Dir(mustReal(sys))
	}
	if b, err := os.ReadFile(filepath.Join(disk, "removable")); err == nil && strings.TrimSpace(string(b)) == "1" {
		return true
	}
	return strings.Contains(mustReal(disk), "/usb")
}

func mustReal(p string) string {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return r
}

func (s *Service) devNumbers() (map[string]string, error) {
	f, err := os.Open(s.cfg.MountInfo)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		if _, ok := out[fields[2]]; !ok {
			out[fields[2]] = unescape(fields[4])
		}
	}
	return out, sc.Err()
}

func unescape(p string) string {
	if !strings.Contains(p, `\`) {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+3 < len(p) {
			if v, err := strconv.ParseUint(p[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

func (s *Service) peek(name string) (*key.Key, string, error) {
	dir := filepath.Join(s.cfg.PeekDir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	defer os.Remove(dir)
	if err := s.cfg.Mounter.Mount(filepath.Join(s.cfg.SysRoot, "dev", name), dir, "", true); err != nil {
		return nil, "", err
	}
	defer s.cfg.Mounter.Unmount(dir)
	k, err := key.Open(dir)
	return k, "", err
}

func (s *Service) Scan() {
	entries, err := os.ReadDir(filepath.Join(s.cfg.SysRoot, "sys/class/block"))
	if err != nil {
		return
	}
	mounted, _ := s.devNumbers()
	for num, root := range mounted {
		if strings.HasPrefix(root, s.cfg.PeekDir+"/") && s.cfg.Mounter.Unmount(root) == nil {
			os.Remove(root)
			delete(mounted, num)
		}
	}
	found := []PresentKey{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") || !s.removable(name) {
			continue
		}
		num, err := os.ReadFile(filepath.Join(s.cfg.SysRoot, "sys/class/block", name, "dev"))
		if err != nil {
			continue
		}
		var k *key.Key
		root := mounted[strings.TrimSpace(string(num))]
		if root != "" {
			k, err = key.Open(root)
			if err != nil && !errors.Is(err, keyfile.ErrNoKey) && !errors.Is(err, os.ErrNotExist) {
				log.Printf("%s: %v, reading it again from a private mount", name, err)
				k, _, err = s.peek(name)
			}
		} else {
			k, _, err = s.peek(name)
		}
		if err != nil {
			if !errors.Is(err, keyfile.ErrNoKey) && !errors.Is(err, os.ErrNotExist) && root != "" {
				log.Printf("%s: %v", name, err)
			}
			continue
		}
		state := StateLocked
		s.mu.Lock()
		if u, ok := s.open[root]; ok && root != "" {
			state = u.mode
		}
		s.mu.Unlock()
		if state == StateLocked && k.Copy(s.cfg.TPM) {
			state = StateCopy
		}
		found = append(found, PresentKey{"/dev/" + name, k.Header.ID, k.Header.Owner, state})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Device < found[j].Device })
	s.mu.Lock()
	s.present = found
	s.mu.Unlock()
	s.setProp("Present", found)
}

func (s *Service) setProp(name string, v interface{}) {
	if s.props == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s not published: %v", name, r)
		}
	}()
	s.props.SetMust(Iface, name, v)
}

func (s *Service) Present() []PresentKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PresentKey(nil), s.present...)
}

func (s *Service) FollowDevices() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_KOBJECT_UEVENT)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}); err != nil {
		return err
	}
	s.Scan()
	buf := make([]byte, 8192)
	pending := make(chan struct{}, 1)
	go func() {
		for range pending {
			time.Sleep(700 * time.Millisecond)
			s.Scan()
		}
	}()
	for {
		n, err := syscall.Read(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		msg := string(buf[:n])
		if strings.Contains(msg, "SUBSYSTEM=block") || strings.Contains(msg, "/block/") {
			select {
			case pending <- struct{}{}:
			default:
			}
		}
	}
}

func (s *Service) senderUID(sender dbus.Sender) (uint32, error) {
	if s.conn == nil {
		return 0, errors.New("no bus")
	}
	var uid uint32
	err := s.conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid)
	return uid, err
}

func (s *Service) attachAllowed(uid uint32) bool {
	if uid == 0 {
		return true
	}
	for _, name := range s.cfg.AttachUsers {
		if u, err := user.Lookup(name); err == nil && u.Uid == strconv.FormatUint(uint64(uid), 10) {
			return true
		}
	}
	return false
}

func (s *Service) Attach(sender dbus.Sender, device, username, pin string) (string, string, *dbus.Error) {
	uid, err := s.senderUID(sender)
	if err != nil || !s.attachAllowed(uid) {
		return "", "", dbus.NewError(errorPfx+"NotAllowed", []interface{}{"only the login screen can attach a Key"})
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
	u, err := user.Lookup(username)
	if err != nil {
		return "", "", fail(err)
	}
	mounted, _ := s.devNumbers()
	name := filepath.Base(device)
	num, _ := os.ReadFile(filepath.Join(s.cfg.SysRoot, "sys/class/block", name, "dev"))
	root := mounted[strings.TrimSpace(string(num))]
	if root == "" {
		base := filepath.Join(s.cfg.SysRoot, "run/media", username)
		if err := os.MkdirAll(base, 0o750); err != nil {
			return "", "", fail(err)
		}
		gid, _ := strconv.Atoi(u.Gid)
		uidn, _ := strconv.Atoi(u.Uid)
		_ = os.Chown(base, 0, gid)
		root = filepath.Join(base, "Sinty Key "+dev.ID[:min(6, len(dev.ID))])
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", "", fail(err)
		}
		opts := fmt.Sprintf("uid=%d,gid=%d,fmask=0077,dmask=0077", uidn, gid)
		if err := s.cfg.Mounter.Mount(filepath.Join(s.cfg.SysRoot, "dev", name), root, opts, false); err != nil {
			os.Remove(root)
			return "", "", fail(err)
		}
		_ = os.Chown(root, uidn, gid)
	}
	mode, derr := s.Unlock(root, pin)
	s.Scan()
	if derr != nil {
		return root, "", derr
	}
	return root, mode, nil
}
