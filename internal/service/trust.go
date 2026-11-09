package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/godbus/dbus/v5"
)

const KindKey = "key"

var errUnknownDevice = errors.New("this device is not trusted here")

type Device struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Counter uint32 `json:"counter,omitempty"`
	Added   int64  `json:"added"`
	Last    int64  `json:"last"`
}

type DeviceInfo struct {
	Kind  string
	ID    string
	Name  string
	Added int64
	Last  int64
}

func (s *Service) loadTrust() []Device {
	if s.cfg.TrustFile == "" {
		return nil
	}
	data, err := os.ReadFile(s.cfg.TrustFile)
	if err != nil {
		return nil
	}
	var list []Device
	if json.Unmarshal(data, &list) != nil {
		return nil
	}
	return list
}

func (s *Service) saveTrust(list []Device) error {
	if s.cfg.TrustFile == "" {
		return nil
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Kind != list[j].Kind {
			return list[i].Kind < list[j].Kind
		}
		return list[i].ID < list[j].ID
	})
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.TrustFile), 0o700); err != nil {
		return err
	}
	tmp := s.cfg.TrustFile + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfg.TrustFile)
}

func (s *Service) trust(d Device) {
	list := s.loadTrust()
	now := time.Now().Unix()
	for i := range list {
		if list[i].Kind == d.Kind && list[i].ID == d.ID {
			if d.Name != "" {
				list[i].Name = d.Name
			}
			if d.Counter != 0 {
				list[i].Counter = d.Counter
			}
			list[i].Last = now
			s.saveTrust(list)
			return
		}
	}
	d.Added, d.Last = now, now
	s.saveTrust(append(list, d))
}

func (s *Service) seen(kind, id string) {
	list := s.loadTrust()
	for i := range list {
		if list[i].Kind == kind && list[i].ID == id {
			list[i].Last = time.Now().Unix()
			s.saveTrust(list)
			return
		}
	}
}

func (s *Service) untrust(kind, id string) (Device, bool) {
	list := s.loadTrust()
	for i := range list {
		if list[i].Kind == kind && list[i].ID == id {
			d := list[i]
			s.saveTrust(append(list[:i], list[i+1:]...))
			return d, true
		}
	}
	return Device{}, false
}

func (s *Service) Devices() ([]DeviceInfo, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []DeviceInfo{}
	for _, d := range s.loadTrust() {
		out = append(out, DeviceInfo{d.Kind, d.ID, d.Name, d.Added, d.Last})
	}
	return out, nil
}

func (s *Service) Revoke(kind, id string) *dbus.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.loadTrust()
	for _, d := range list {
		if d.Kind != kind || d.ID != id {
			continue
		}
		if kind == KindKey && s.cfg.TPM != nil {
			if _, err := s.cfg.TPM.Bump(d.Counter); err != nil {
				return fail(err)
			}
		}
		s.untrust(kind, id)
		if s.conn != nil {
			s.conn.Emit(Path, Iface+".Revoked", kind, id)
		}
		return nil
	}
	return dbus.NewError(errorPfx+"Unknown", []interface{}{errUnknownDevice.Error()})
}

func (s *Service) Trust(sender dbus.Sender, kind, id, name string) *dbus.Error {
	uid, err := s.senderUID(sender)
	if err != nil || uid != uint32(os.Getuid()) {
		return dbus.NewError(errorPfx+"NotAllowed", []interface{}{"only system services can add trusted devices"})
	}
	if kind == "" || kind == KindKey || id == "" {
		return dbus.NewError(errorPfx+"NotAllowed", []interface{}{"a Sinty Key is trusted by remembering it"})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trust(Device{Kind: kind, ID: id, Name: name})
	return nil
}
