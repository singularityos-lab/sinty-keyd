package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"
)

const (
	healthName  = "dev.sinty.DiskHealth"
	healthPath  = dbus.ObjectPath("/dev/sinty/DiskHealth")
	healthIface = "dev.sinty.DiskHealth1"
)

var errFakeDrive = errors.New("this drive reports more space than it really has, it would lose data: use another drive")

func (s *Service) healthAvailable() bool {
	if s.conn == nil {
		return false
	}
	var owned bool
	if err := s.conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, healthName).Store(&owned); err != nil {
		return false
	}
	return owned
}

func (s *Service) checkCapacity(dev string) error {
	if !s.healthAvailable() {
		return nil
	}
	var ok bool
	var real uint64
	call := s.conn.Object(healthName, healthPath).Call(healthIface+".VerifyCapacity", 0, dev)
	if call.Err != nil {
		var e dbus.Error
		if errors.As(call.Err, &e) && strings.HasSuffix(e.Name, ".UnknownMethod") {
			return nil
		}
		return fmt.Errorf("checking the drive: %w", call.Err)
	}
	if err := call.Store(&ok, &real); err != nil {
		return err
	}
	if ok {
		return nil
	}
	size, _ := strconv.ParseUint(readTrim(filepath.Join(s.blockDir(filepath.Base(dev)), "size")), 10, 64)
	if size > 0 && real < size*512 {
		return errFakeDrive
	}
	return errDriveWorn
}

func (s *Service) reportCheck(dev, check string, ok bool, detail string) {
	if dev == "" || !s.healthAvailable() {
		return
	}
	s.conn.Object(healthName, healthPath).Go(healthIface+".Report", dbus.FlagNoReplyExpected, nil, dev, check, ok, detail)
}

func (s *Service) deviceOf(f *os.File) string {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return ""
	}
	major := (st.Dev >> 8) & 0xfff
	minor := (st.Dev & 0xff) | ((st.Dev >> 12) & 0xfff00)
	link, err := filepath.EvalSymlinks(filepath.Join(s.cfg.SysRoot, "sys/dev/block", fmt.Sprintf("%d:%d", major, minor)))
	if err != nil {
		return ""
	}
	return "/dev/" + filepath.Base(link)
}

func (s *Service) reportStartup(dev string, err error) {
	switch {
	case err == nil:
		s.reportCheck(dev, "startup-key", true, "")
	case errors.Is(err, errDriveWorn):
		s.reportCheck(dev, "startup-key", false, err.Error())
	}
}
