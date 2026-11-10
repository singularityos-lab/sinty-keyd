package service

import (
	"errors"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/badge"
)

const badgeGrace = 2 * time.Minute

var (
	errBadgeOff  = errors.New("this computer does not open sessions from a Sinty Key")
	errBadgeBusy = errors.New("a session from a Sinty Key is already open")
	errNoBadge   = errors.New("no session from a Sinty Key is open")
)

type badgeSession struct {
	id      string
	device  string
	root    string
	gone    *time.Timer
	removed bool
}

func (s *Service) badgeDir() string {
	return filepath.Join(s.cfg.SysRoot, "run/sinty-badge")
}

func (s *Service) badgeRoot() string {
	return filepath.Join(s.cfg.SysRoot, "run/media", badge.User, "Key")
}

func (s *Service) BadgeAllowed() (bool, *dbus.Error) {
	return badge.Allowed(s.cfg.BadgePolicy), nil
}

func (s *Service) admin(sender dbus.Sender) bool {
	uid, err := s.senderUID(sender)
	if err != nil {
		return false
	}
	if uid == 0 {
		return true
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	groups, _ := u.GroupIds()
	for _, name := range []string{"wheel", "sudo", "admin"} {
		if g, err := user.LookupGroup(name); err == nil && slices.Contains(groups, g.Gid) {
			return true
		}
	}
	return false
}

func (s *Service) SetBadgeAllowed(sender dbus.Sender, on bool) *dbus.Error {
	if !s.admin(sender) {
		return dbus.NewError(errorPfx+"NotAllowed", []interface{}{"only an administrator can change this"})
	}
	if err := badge.SetAllowed(s.cfg.BadgePolicy, on); err != nil {
		return fail(err)
	}
	s.setProp("BadgeAllowed", on)
	return nil
}

func badgeError(err error) *dbus.Error {
	switch {
	case errors.Is(err, errBadgeOff):
		return dbus.NewError(errorPfx+"Disabled", []interface{}{err.Error()})
	case errors.Is(err, badge.ErrUnverified):
		return dbus.NewError(errorPfx+"Unverified", []interface{}{err.Error()})
	case errors.Is(err, errBadgeBusy):
		return dbus.NewError(errorPfx+"Busy", []interface{}{err.Error()})
	}
	return fail(err)
}

func (s *Service) Badge(sender dbus.Sender, device, pin string) (string, string, *dbus.Error) {
	uid, err := s.senderUID(sender)
	if err != nil || !s.attachAllowed(uid) {
		return "", "", dbus.NewError(errorPfx+"NotAllowed", []interface{}{"only the login screen can open a session from a Key"})
	}
	user, ticket, err := s.openBadge(device, pin)
	if err != nil {
		var derr *dbus.Error
		if errors.As(err, &derr) {
			return "", "", derr
		}
		return "", "", badgeError(err)
	}
	return user, ticket, nil
}

func (s *Service) openBadge(device, pin string) (string, string, error) {
	if !badge.Allowed(s.cfg.BadgePolicy) {
		return "", "", errBadgeOff
	}
	if err := s.cfg.Verify(s.cfg.SysRoot); err != nil {
		return "", "", err
	}
	s.mu.Lock()
	busy := s.badge != nil
	s.mu.Unlock()
	if busy {
		return "", "", errBadgeBusy
	}
	var dev *PresentKey
	for _, p := range s.Present() {
		if p.Device == device {
			dev = &p
			break
		}
	}
	if dev == nil {
		return "", "", errUnknownDevice
	}
	root, err := s.mountBadge(device)
	if err != nil {
		return "", "", err
	}
	ok := false
	defer func() {
		if !ok {
			s.closeBadge(root)
		}
	}()
	if _, derr := s.Unlock(root, pin); derr != nil {
		return "", "", derr
	}
	home, uid, gid, err := badgeHome(root)
	if err != nil {
		return "", "", err
	}
	if err := badge.AddAccount(filepath.Join(s.cfg.SysRoot, "etc"), dev.Owner); err != nil {
		return "", "", err
	}
	target := filepath.Join(s.cfg.SysRoot, badge.Home)
	if err := os.MkdirAll(target, 0o700); err != nil {
		return "", "", err
	}
	if err := s.cfg.MapHome(home, target, uid, gid, badge.UID, badge.UID); err != nil {
		return "", "", err
	}
	ticket, err := badge.NewTicket(filepath.Join(s.badgeDir(), "ticket"))
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	s.badge = &badgeSession{id: dev.ID, device: device, root: root}
	s.mu.Unlock()
	s.setProp("Badge", dev.ID)
	ok = true
	return badge.User, ticket, nil
}

func badgeHome(root string) (string, int, int, error) {
	data, err := os.Stat(filepath.Join(root, DataDir))
	if err != nil {
		return "", 0, 0, err
	}
	st := data.Sys().(*syscall.Stat_t)
	home := filepath.Join(root, DataDir, "Home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return "", 0, 0, err
	}
	if err := os.Lchown(home, int(st.Uid), int(st.Gid)); err != nil {
		return "", 0, 0, err
	}
	return home, int(st.Uid), int(st.Gid), nil
}

func (s *Service) mountBadge(device string) (string, error) {
	root := s.badgeRoot()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	if err := s.cfg.Mounter.Mount(filepath.Join(s.cfg.SysRoot, "dev", filepath.Base(device)), root, "", false); err != nil {
		os.Remove(root)
		return "", err
	}
	return root, nil
}

func (s *Service) closeBadge(root string) {
	target := filepath.Join(s.cfg.SysRoot, badge.Home)
	if err := s.cfg.Mounter.Unmount(target); err != nil && !errors.Is(err, syscall.EINVAL) && !os.IsNotExist(err) {
		log.Printf("badge home: %v", err)
	}
	os.Remove(target)
	if root != "" {
		if derr := s.Lock(root); derr != nil {
			log.Printf("badge lock: %v", derr.Body)
		}
		if err := s.cfg.Mounter.Unmount(root); err != nil {
			log.Printf("badge key: %v", err)
		}
		os.Remove(root)
		s.mu.Lock()
		delete(s.open, root)
		s.mu.Unlock()
	}
	if err := badge.RemoveAccount(filepath.Join(s.cfg.SysRoot, "etc")); err != nil {
		log.Printf("badge account: %v", err)
	}
	os.Remove(filepath.Join(s.badgeDir(), "ticket"))
}

func (s *Service) EndBadge(sender dbus.Sender) *dbus.Error {
	uid, err := s.senderUID(sender)
	if err != nil || (uid != badge.UID && !s.attachAllowed(uid)) {
		return dbus.NewError(errorPfx+"NotAllowed", []interface{}{"not allowed"})
	}
	return s.endBadge(false)
}

func (s *Service) endBadge(kill bool) *dbus.Error {
	s.mu.Lock()
	b := s.badge
	s.badge = nil
	s.mu.Unlock()
	if b == nil {
		return badgeError(errNoBadge)
	}
	if b.gone != nil {
		b.gone.Stop()
	}
	if kill {
		for _, pid := range badge.Processes(filepath.Join(s.cfg.SysRoot, "proc"), badge.UID) {
			syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	s.closeBadge(b.root)
	s.setProp("Badge", "")
	return nil
}

func (s *Service) ResumeBadge(sender dbus.Sender, pin string) *dbus.Error {
	uid, err := s.senderUID(sender)
	if err != nil || (uid != badge.UID && uid != 0) {
		return dbus.NewError(errorPfx+"NotAllowed", []interface{}{"not allowed"})
	}
	return s.resumeBadge(pin)
}

func (s *Service) resumeBadge(pin string) *dbus.Error {
	s.mu.Lock()
	b := s.badge
	s.mu.Unlock()
	if b == nil {
		return badgeError(errNoBadge)
	}
	var dev *PresentKey
	for _, p := range s.Present() {
		if p.ID == b.id {
			dev = &p
			break
		}
	}
	if dev == nil {
		return fail(errUnknownDevice)
	}
	target := filepath.Join(s.cfg.SysRoot, badge.Home)
	if b.removed {
		s.cfg.Mounter.Unmount(target)
		s.cfg.Mounter.Unmount(b.root)
		s.mu.Lock()
		delete(s.open, b.root)
		s.mu.Unlock()
		if _, err := s.mountBadge(dev.Device); err != nil {
			return fail(err)
		}
	}
	if _, derr := s.Unlock(b.root, pin); derr != nil {
		return derr
	}
	if b.removed {
		home, uid, gid, err := badgeHome(b.root)
		if err != nil {
			return fail(err)
		}
		if err := s.cfg.MapHome(home, target, uid, gid, badge.UID, badge.UID); err != nil {
			return fail(err)
		}
	}
	s.mu.Lock()
	if b.gone != nil {
		b.gone.Stop()
		b.gone = nil
	}
	b.removed = false
	b.device = dev.Device
	s.mu.Unlock()
	s.emit("BadgeKeyReturned")
	return nil
}

func (s *Service) watchBadge(found []PresentKey) {
	s.mu.Lock()
	b := s.badge
	if b == nil {
		s.mu.Unlock()
		return
	}
	here := slices.ContainsFunc(found, func(p PresentKey) bool { return p.ID == b.id })
	leaving := !here && !b.removed
	if leaving {
		b.removed = true
		b.gone = time.AfterFunc(s.cfg.BadgeGrace, func() {
			s.mu.Lock()
			still := s.badge == b && b.removed
			s.mu.Unlock()
			if still {
				s.endBadge(true)
			}
		})
	}
	s.mu.Unlock()
	if leaving {
		s.emit("BadgeKeyRemoved")
	}
}

func (s *Service) emit(name string) {
	if s.conn != nil {
		s.conn.Emit(Path, Iface+"."+name)
	}
}
