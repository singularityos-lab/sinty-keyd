package service

import (
	"encoding/hex"
	"errors"
	"path/filepath"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/fido2"
	"github.com/singularityos-lab/sinty-keyd/internal/key"
)

type SecurityKeyInfo struct {
	ID    string
	Name  string
	Added int64
}

type securityKeys struct {
	open func() ([]fido2.Transport, error)
}

func hidKeys(sysRoot string) func() ([]fido2.Transport, error) {
	return func() ([]fido2.Transport, error) {
		var out []fido2.Transport
		for _, path := range fido2.Devices(filepath.Join(sysRoot, "sys")) {
			h, err := fido2.OpenHID(filepath.Join(sysRoot, path))
			if err != nil {
				continue
			}
			out = append(out, h)
		}
		return out, nil
	}
}

func closeAll(ts []fido2.Transport) {
	for _, t := range ts {
		t.Close()
	}
}

func (p securityKeys) devices() ([]fido2.Transport, error) {
	ts, err := p.open()
	if err != nil {
		return nil, err
	}
	if len(ts) == 0 {
		return nil, key.ErrFactorRequired
	}
	return ts, nil
}

func (p securityKeys) Secret(rpID string, ids [][]byte, salt []byte) ([]byte, []byte, error) {
	ts, err := p.devices()
	if err != nil {
		return nil, nil, err
	}
	defer closeAll(ts)
	last := fido2.ErrNoCredential
	for _, t := range ts {
		id, out, err := (&fido2.Client{T: t}).Secret(rpID, ids, salt)
		if err == nil {
			return id, out, nil
		}
		if !errors.Is(err, fido2.ErrNoCredential) {
			last = err
		}
	}
	return nil, nil, last
}

func (p securityKeys) Register(rpID, pin string, exclude [][]byte) ([]byte, error) {
	ts, err := p.devices()
	if err != nil {
		return nil, err
	}
	defer closeAll(ts)
	last := fido2.ErrExcluded
	for _, t := range ts {
		c := &fido2.Client{T: t}
		id, err := c.Register(rpID, pin, exclude)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, fido2.ErrExcluded) {
			last = err
		}
	}
	return nil, last
}

func (s *Service) openKey(root string) (*key.Key, error) {
	k, err := key.Open(root)
	if err != nil {
		return nil, err
	}
	k.Second = s.keys
	return k, nil
}

func (s *Service) SecurityKeys(root string) ([]SecurityKeyInfo, *dbus.Error) {
	r, err := s.place(root)
	if err != nil {
		return nil, fail(err)
	}
	k, err := key.Open(r)
	if err != nil {
		return nil, fail(err)
	}
	out := []SecurityKeyInfo{}
	for _, f := range k.Header.Factors {
		out = append(out, SecurityKeyInfo{hex.EncodeToString(f.ID), f.Name, f.Added.Unix()})
	}
	return out, nil
}

func (s *Service) AddSecurityKey(root, pin, name, devicePin string) (string, *dbus.Error) {
	var id []byte
	err := s.withKey(root, func(k *key.Key) error {
		var err error
		id, err = k.AddFactor(s.cfg.TPM, pin, s.keys, name, devicePin)
		return err
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id), nil
}

func (s *Service) RemoveSecurityKey(root, pin, id string) *dbus.Error {
	raw, err := hex.DecodeString(id)
	if err != nil {
		return fail(key.ErrNoFactor)
	}
	return s.withKey(root, func(k *key.Key) error {
		return k.RemoveFactor(s.cfg.TPM, pin, raw)
	})
}

func (s *Service) RecoverWithoutSecurityKeys(root, code, pin string) *dbus.Error {
	return s.withKey(root, func(k *key.Key) error {
		return k.RecoverWithoutFactors(s.cfg.TPM, code, pin)
	})
}

func securityKeyError(err error) string {
	switch {
	case errors.Is(err, key.ErrFactorRequired):
		return "SecurityKeyRequired"
	case errors.Is(err, key.ErrUnknownFactor):
		return "UnknownSecurityKey"
	case errors.Is(err, key.ErrFactorExists):
		return "SecurityKeyExists"
	case errors.Is(err, key.ErrTooManyFactors):
		return "TooManySecurityKeys"
	case errors.Is(err, key.ErrNoFactor):
		return "NoSecurityKey"
	case errors.Is(err, fido2.ErrDenied), errors.Is(err, fido2.ErrTimeout):
		return "NotTouched"
	case errors.Is(err, fido2.ErrPINRequired):
		return "SecurityKeyPinRequired"
	case errors.Is(err, fido2.ErrPINInvalid):
		return "WrongSecurityKeyPin"
	case errors.Is(err, fido2.ErrPINBlocked):
		return "SecurityKeyPinBlocked"
	case errors.Is(err, fido2.ErrNoHmacSecret):
		return "SecurityKeyUnsupported"
	}
	return ""
}

var _ key.Registrar = securityKeys{}
