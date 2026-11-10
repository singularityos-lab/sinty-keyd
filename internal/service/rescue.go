package service

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
)

const rescueWait = 60 * time.Second

var (
	errNotPortable = errors.New("this computer is not running from a Sinty Key")
	errNoTarget    = errors.New("this drive does not hold a Sinty installation")
	errRescueBusy  = errors.New("a rescue is already running")
	errNoRescue    = errors.New("no rescue is running")
	errNotYours    = errors.New("this rescue was started by someone else")
)

type rescueRun struct {
	cmd    *exec.Cmd
	uid    int
	socket string
}

func (s *Service) portable() bool {
	cmdline, _ := os.ReadFile(filepath.Join(s.cfg.SysRoot, "proc/cmdline"))
	for _, f := range strings.Fields(string(cmdline)) {
		if f == "sing.portable=1" {
			return true
		}
	}
	return false
}

func (s *Service) disks() []string {
	entries, _ := os.ReadDir(filepath.Join(s.cfg.SysRoot, "sys/class/block"))
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") || strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "sr") {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.blockDir(name), "partition")); err == nil {
			continue
		}
		out = append(out, name)
	}
	return out
}

func (s *Service) bootDisk() string {
	mounted, _ := s.devNumbers()
	for _, disk := range s.disks() {
		for _, p := range s.partitions(disk) {
			if root := s.mountOf(p, mounted); root == "/var" || root == "/" {
				return disk
			}
		}
	}
	return ""
}

func (s *Service) rescueTargets() []DriveInfo {
	if !s.portable() {
		return []DriveInfo{}
	}
	boot := s.bootDisk()
	mounted, _ := s.devNumbers()
	out := []DriveInfo{}
	for _, disk := range s.disks() {
		if disk == boot || s.removable(disk) {
			continue
		}
		data, busy := false, false
		for _, p := range s.partitions(disk) {
			if s.partLabel(p) == "atom-data" {
				data = true
			}
			if !userMount(s.mountOf(p, mounted)) {
				busy = true
			}
		}
		if !data || busy {
			continue
		}
		sectors, _ := strconv.ParseUint(readTrim(filepath.Join(s.blockDir(disk), "size")), 10, 64)
		dev := filepath.Join(s.blockDir(disk), "device")
		name := strings.TrimSpace(readTrim(filepath.Join(dev, "vendor")) + " " + readTrim(filepath.Join(dev, "model")))
		if name == "" {
			name = "Internal Drive"
		}
		out = append(out, DriveInfo{Device: "/dev/" + disk, Name: name, Size: sectors * 512, Startup: true})
	}
	return out
}

func (s *Service) RescueTargets(sender dbus.Sender) ([]DriveInfo, *dbus.Error) {
	if _, derr := s.caller(sender); derr != nil {
		return nil, derr
	}
	return s.rescueTargets(), nil
}

func (s *Service) rescueRoot() string {
	return filepath.Join(s.cfg.SysRoot, "run/sinty-rescue")
}

func (s *Service) Rescue(sender dbus.Sender, device string) (string, *dbus.Error) {
	if !s.admin(sender) {
		return "", dbus.NewError(errorPfx+"NotAllowed", []interface{}{"only an administrator can rescue a computer"})
	}
	u, derr := s.caller(sender)
	if derr != nil {
		return "", derr
	}
	sock, err := s.startRescue(u, device)
	if err != nil {
		return "", fail(err)
	}
	return sock, nil
}

func (s *Service) startRescue(u *user.User, device string) (string, error) {
	if !s.portable() {
		return "", errNotPortable
	}
	disk := filepath.Base(device)
	var target *DriveInfo
	for _, t := range s.rescueTargets() {
		if t.Device == "/dev/"+disk {
			target = &t
			break
		}
	}
	if target == nil {
		return "", errNoTarget
	}
	data := ""
	for _, p := range s.partitions(disk) {
		if s.partLabel(p) == "atom-data" {
			data = p
		}
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	s.mu.Lock()
	if s.rescue != nil {
		s.mu.Unlock()
		return "", errRescueBusy
	}
	run := &rescueRun{uid: uid}
	s.rescue = run
	s.mu.Unlock()
	ok := false
	defer func() {
		if !ok {
			s.mu.Lock()
			s.rescue = nil
			s.mu.Unlock()
		}
	}()
	out := filepath.Join(u.HomeDir, "Rescued")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", err
	}
	if err := os.Lchown(out, uid, gid); err != nil {
		return "", err
	}
	root := s.rescueRoot()
	if err := os.MkdirAll(root, 0o711); err != nil {
		return "", err
	}
	run.socket = filepath.Join(root, "recovery.sock")
	os.Remove(run.socket)
	keyESP := ""
	if boot := s.bootDisk(); boot != "" {
		keyESP = "/dev/" + partName(boot, 1)
	}
	run.cmd = exec.Command(s.cfg.Rescue, "/dev/"+data, "/dev/"+partName(disk, 1), keyESP, out, run.socket)
	run.cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	run.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := run.cmd.Start(); err != nil {
		return "", err
	}
	exited := make(chan struct{})
	go func() {
		run.cmd.Wait()
		os.Remove(run.socket)
		close(exited)
		s.mu.Lock()
		if s.rescue == run {
			s.rescue = nil
		}
		s.mu.Unlock()
	}()
	deadline := time.After(rescueWait)
	for {
		if _, err := os.Stat(run.socket); err == nil {
			break
		}
		select {
		case <-exited:
			return "", errors.New("the rescue could not start on this drive")
		case <-deadline:
			syscall.Kill(-run.cmd.Process.Pid, syscall.SIGTERM)
			return "", errors.New("the rescue did not start in time")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := os.Chown(run.socket, uid, gid); err != nil {
		syscall.Kill(-run.cmd.Process.Pid, syscall.SIGTERM)
		return "", err
	}
	ok = true
	return run.socket, nil
}

func (s *Service) EndRescue(sender dbus.Sender) *dbus.Error {
	uid, err := s.senderUID(sender)
	if err != nil {
		return fail(err)
	}
	if err := s.endRescue(int(uid)); err != nil {
		if errors.Is(err, errNotYours) {
			return dbus.NewError(errorPfx+"NotAllowed", []interface{}{"not allowed"})
		}
		return fail(err)
	}
	return nil
}

func (s *Service) endRescue(uid int) error {
	s.mu.Lock()
	run := s.rescue
	s.mu.Unlock()
	if run == nil {
		return errNoRescue
	}
	if uid != run.uid && uid != 0 {
		return errNotYours
	}
	return syscall.Kill(-run.cmd.Process.Pid, syscall.SIGTERM)
}
