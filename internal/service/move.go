package service

import (
	"errors"
	"os/user"
	"strconv"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"github.com/singularityos-lab/sinty-keyd/internal/migrate"
)

const (
	MoveToKey   = "to-key"
	MoveFromKey = "from-key"
)

var (
	errKeyLocked     = errors.New("open the Key with its PIN first")
	errNoSpace       = errors.New("there is not enough free space for this home")
	errMoveDirection = errors.New("unknown direction")
	errNotVerified   = errors.New("the copy was not checked yet")
)

type move struct {
	src, dst, source string
	owner            migrate.Owner
}

func (s *Service) moveUser(sender dbus.Sender, name string) (*user.User, *dbus.Error) {
	if name == "" {
		return s.caller(sender)
	}
	uid, err := s.senderUID(sender)
	if err != nil {
		return nil, fail(err)
	}
	if uid != 0 {
		return nil, dbus.NewError(errorPfx+"NotAllowed", []interface{}{"only the setup assistant can move another account's home"})
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fail(err)
	}
	if id, _ := strconv.Atoi(u.Uid); id < 1000 {
		return nil, dbus.NewError(errorPfx+"NotAllowed", []interface{}{"not allowed"})
	}
	return u, nil
}

func (s *Service) movePlan(u *user.User, root, direction string) (move, error) {
	r, err := s.place(root)
	if err != nil {
		return move{}, err
	}
	s.mu.Lock()
	_, open := s.open[r]
	s.mu.Unlock()
	if !open {
		return move{}, errKeyLocked
	}
	keyHome, kuid, kgid, err := badgeHome(r)
	if err != nil {
		return move{}, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	m := move{source: direction + ":" + u.Username}
	switch direction {
	case MoveToKey:
		m.src, m.dst, m.owner = u.HomeDir, keyHome, migrate.Owner{UID: kuid, GID: kgid}
	case MoveFromKey:
		m.src, m.dst, m.owner = keyHome, u.HomeDir, migrate.Owner{UID: uid, GID: gid}
	default:
		return move{}, errMoveDirection
	}
	return m, nil
}

func freeSpace(dir string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func (s *Service) moveHome(u *user.User, root, direction string) error {
	s.moveMu.Lock()
	defer s.moveMu.Unlock()
	m, err := s.movePlan(u, root, direction)
	if err != nil {
		return err
	}
	need, err := migrate.Size(m.src)
	if err != nil {
		return err
	}
	have, _ := migrate.Size(m.dst)
	free, err := freeSpace(m.dst)
	if err != nil {
		return err
	}
	if need-have > free {
		return errNoSpace
	}
	report := func(from, span uint32) migrate.Progress {
		return func(done, total int64) {
			pct := uint32(100)
			if total > 0 {
				pct = uint32(done * 100 / total)
			}
			s.progress(root, from+span*pct/100)
		}
	}
	if err := migrate.Copy(m.src, m.dst, m.source, m.owner, report(0, 70)); err != nil {
		return err
	}
	return migrate.Verify(m.src, m.dst, m.source, report(70, 30))
}

func (s *Service) MoveHome(sender dbus.Sender, root, name, direction string) *dbus.Error {
	u, derr := s.moveUser(sender, name)
	if derr != nil {
		return derr
	}
	if err := s.moveHome(u, root, direction); err != nil {
		return fail(err)
	}
	return nil
}

func (s *Service) MoveHomeState(sender dbus.Sender, root, name, direction string) (string, *dbus.Error) {
	u, derr := s.moveUser(sender, name)
	if derr != nil {
		return "", derr
	}
	m, err := s.movePlan(u, root, direction)
	if err != nil {
		return "", fail(err)
	}
	return migrate.State(m.dst, m.source), nil
}

func (s *Service) FinishMove(sender dbus.Sender, root, name, direction string, remove bool) *dbus.Error {
	u, derr := s.moveUser(sender, name)
	if derr != nil {
		return derr
	}
	if err := s.finishMove(u, root, direction, remove); err != nil {
		return fail(err)
	}
	return nil
}

func (s *Service) finishMove(u *user.User, root, direction string, remove bool) error {
	s.moveMu.Lock()
	defer s.moveMu.Unlock()
	m, err := s.movePlan(u, root, direction)
	if err != nil {
		return err
	}
	if migrate.State(m.dst, m.source) != migrate.Verified {
		return errNotVerified
	}
	if !remove {
		return migrate.Finish(m.dst)
	}
	return migrate.RemoveSource(m.src, m.dst, m.source)
}
